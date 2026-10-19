#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Refresh the recorded test times that balance the CI shards.

The shard scripts (go_test_shards.py, python_test_shards.py) read these
files; a test, module or package missing from them still runs, it just
weighs an estimate. Refresh after a large test change:

  go     go test -json output (CI flags: -race, coverage) of the sharded
         packages and the remaining packages -> scripts/test-timings/go-linux.json
           go test -race -gcflags=modernc.org/...=-d=checkptr=0 -count=1 -json ./... > go.json
           scripts/update_test_timings.py go go.json
  python pytest --junitxml reports of the Python suite -> python-linux.json
           pytest cli/tests --junitxml=py.xml ...; scripts/update_test_timings.py python py.xml
  go-ci-log  CI job logs of the Go race shards ("ok <package> <seconds>s"
         lines): replaces the package times in go-linux.json with what the
         hosted runners measured and keeps the per-test times
           gh run view <run> --log > ci.log; scripts/update_test_timings.py go-ci-log ci.log
  windows-go  Windows Native CI job logs of the windows-go packages parts,
         which print "[go-package-time] <package> <result> <seconds>" ->
         go-windows.json (gh run view --log > win.log)
"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "scripts" / "test-timings"
# Packages whose tests the CI splits by test name (go_test_shards.py test
# mode and the split parts of package mode); only their per-test times are kept.
PER_TEST_MIN_SECONDS = 60.0


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")


def go_timings(files: list[Path], module: str) -> dict:
    tests: dict[str, dict[str, float]] = {}
    packages: dict[str, float] = {}
    for file in files:
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("Action") not in ("pass", "fail"):
                continue
            package = event.get("Package", "")
            elapsed = float(event.get("Elapsed", 0))
            name = event.get("Test")
            if name is None:
                # Shards of one package each report its elapsed time: sum them.
                packages[package] = packages.get(package, 0.0) + elapsed
            elif "/" not in name:
                rel = package[len(module) + 1 :] if package.startswith(module + "/") else package
                tests.setdefault(rel, {})[name] = elapsed
    # Per-test times matter only where CI splits a package by test; keep the
    # packages that reach a minute so the file stays reviewable.
    # Tests under two seconds are kept only as their mean ("*"), which is what
    # an unlisted test weighs.
    kept: dict[str, dict[str, float]] = {}
    for rel, names in sorted(tests.items()):
        if packages.get(f"{module}/{rel}", 0.0) < PER_TEST_MIN_SECONDS:
            continue
        slow = {name: round(seconds, 1) for name, seconds in sorted(names.items()) if seconds >= 2.0}
        fast = [seconds for name, seconds in names.items() if seconds < 2.0]
        slow["*"] = round(sum(fast) / len(fast), 3) if fast else 0.1
        kept[rel] = slow
    return {
        "packages": {package: round(seconds, 1) for package, seconds in sorted(packages.items())},
        "tests": kept,
    }


def python_timings(files: list[Path]) -> dict:
    seconds: dict[str, float] = {}
    for file in files:
        for case in ET.parse(file).iter("testcase"):
            parts = (case.get("classname") or "").split(".")
            for end in range(len(parts), 0, -1):
                candidate = "/".join(parts[:end]) + ".py"
                if (ROOT / candidate).is_file():
                    seconds[candidate] = seconds.get(candidate, 0.0) + float(case.get("time") or 0)
                    break
    return {"files": {path: round(value, 2) for path, value in sorted(seconds.items())}}


# The Windows parts run one package at a time (-p=1), so every package also
# pays for linking its test binary, which its reported elapsed time leaves out.
WINDOWS_LINK_SECONDS = 6.0


def go_ci_log_timings(files: list[Path], current: Path) -> dict:
    # A package split into -run parts reports once per part: sum them.
    pattern = re.compile(r"^\S*\s*(?:ok|FAIL)\s+(\S+)\s+([0-9.]+)s\b", re.MULTILINE)
    measured: dict[str, float] = {}
    for file in files:
        seen: set[tuple[str, str]] = set()
        for match in pattern.finditer(file.read_text(encoding="utf-8", errors="replace")):
            if (match.group(1), match.group(2)) in seen:
                continue
            seen.add((match.group(1), match.group(2)))
            measured[match.group(1)] = measured.get(match.group(1), 0.0) + float(match.group(2))
    data = json.loads(current.read_text(encoding="utf-8")) if current.is_file() else {"packages": {}, "tests": {}}
    data["packages"].update({package: round(seconds, 1) for package, seconds in measured.items()})
    data["packages"] = dict(sorted(data["packages"].items()))
    return data


def windows_go_timings(files: list[Path]) -> dict:
    pattern = re.compile(r"\[go-package-time\] (\S+) (?:pass|fail|skip) ([0-9.]+)")
    packages: dict[str, float] = {}
    for file in files:
        for match in pattern.finditer(file.read_text(encoding="utf-8", errors="replace")):
            packages[match.group(1)] = float(match.group(2)) + WINDOWS_LINK_SECONDS
    return {"packages": {package: round(value, 1) for package, value in sorted(packages.items())}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("kind", choices=("go", "go-ci-log", "python", "windows-go"))
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, help="output file (default: scripts/test-timings/<kind>.json)")
    args = parser.parse_args()
    module = re.search(r"^module\s+(\S+)", (ROOT / "go.mod").read_text(encoding="utf-8"), re.MULTILINE).group(1)
    if args.kind == "go":
        data, default = go_timings(args.inputs, module), "go-linux.json"
    elif args.kind == "go-ci-log":
        default = "go-linux.json"
        data = go_ci_log_timings(args.inputs, args.out or OUT_DIR / default)
    elif args.kind == "python":
        data, default = python_timings(args.inputs), "python-linux.json"
    else:
        data, default = windows_go_timings(args.inputs), "go-windows.json"
    _write(args.out or OUT_DIR / default, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
