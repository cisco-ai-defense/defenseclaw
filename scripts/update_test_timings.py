#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Refresh the recorded test times that balance the CI shards.

The shard scripts (go_test_shards.py, python_test_shards.py) read these
files; a test, module or package missing from them still runs, it just
weighs an estimate. Refresh after a large test change:

  go     go test -json events -> scripts/test-timings/go-linux.json. Every
         Linux Go race shard of CI uploads its events as a go-test-timings-*
         artifact (scripts/go_test_report.py --timings), so a refresh reads
         what the hosted runners measured:
           gh run download <run> --pattern 'go-test-timings-*' --dir t
           scripts/update_test_timings.py go t/*/*.json
         A local run works too (go test -race ... -json ./... > go.json).
         The darwin connector and gateway parts of Unix Standalone
         Lifecycle upload go-test-timings-darwin-connector-* and
         go-test-timings-darwin-gateway-* (the gateway's unix and darwin
         tests) the same way; --update keeps the other packages of
         go-darwin.json (internal/enterpriseunix):
           gh run download <run> --pattern 'go-test-timings-darwin-*' --dir t
           scripts/update_test_timings.py go t/*/*.json --update --out scripts/test-timings/go-darwin.json
  python pytest --junitxml reports of the Python suite -> python-linux.json
           pytest cli/tests --junitxml=py.xml ...; scripts/update_test_timings.py python py.xml
         Windows Native CI uploads windows-python-junit-<n> reports:
           scripts/update_test_timings.py python junit-windows-*.xml --out scripts/test-timings/python-windows.json
  windows-go  Windows Native CI job logs of the windows-go parts -> go-windows.json:
         package times from the packages parts ("[go-package-time] <package>
         <result> <seconds>") and the gateway, connector, and hookexec test
         times from the go test -json events their parts print
           gh run view <run> --log > win.log; scripts/update_test_timings.py windows-go win.log

A directory input is one run (every file under it); the files named
directly form one run together. With several runs a package or test weighs
the most any run that timed it took (--weigh slowest, the default): the
hosted pool is bimodal (the slow runners take up to twice as long), and a
shard planned on fast runs meets its deadline on a slow one. --weigh median
takes the median run instead; the Windows remaining-package plan uses it,
because its step room (at most 465 s planned of the 1020 s step,
test_windows_remaining_package_shards_leave_room_in_their_step) was set on
median times (GAP-1066). Download each run into its own directory, for example
  for r in <run1> <run2> <run3>; do gh run download $r --pattern 'go-test-timings-*' --dir t/$r; done
  scripts/update_test_timings.py go t/<run1> t/<run2> t/<run3>
A top-level test weighs its share of the package wall time
(go_test_report.TopLevelShares): parallel tests that ran side by side split
the time they shared, and a test of parallel subtests weighs the time they held.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from go_test_report import TopLevelShares  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "scripts" / "test-timings"
# Packages whose tests the CI splits by test name (go_test_shards.py test
# mode and the split parts of package mode); only their per-test times are kept.
PER_TEST_MIN_SECONDS = 60.0
# A top-level test function, as go_test_shards.py discovers them.
TEST_FUNCTION_RE = re.compile(r"^func\s+((?:Test|Fuzz|Example)[A-Za-z0-9_]*)\s*\(", re.MULTILINE)


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")


def _go_events(files: list[Path]):
    """The go test -json events of files, in order."""
    for file in files:
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            # A CI log puts a timestamp (and gh run view the job and step
            # names) before each event.
            start = line.find('{"')
            if start < 0:
                continue
            try:
                event = json.loads(line[start:])
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                yield event


GO_EVENT_TIME_RE = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")


def _event_time(event: dict) -> datetime | None:
    # The Time of a go test -json event (RFC 3339 with nanoseconds), or None.
    match = GO_EVENT_TIME_RE.match(str(event.get("Time", "")))
    if not match:
        return None
    fraction = (match.group(2) or "")[:6].ljust(6, "0")
    zone = "+00:00" if match.group(3) == "Z" else match.group(3)
    return datetime.fromisoformat(f"{match.group(1)}.{fraction}{zone}")


def _rel(package: str, module: str) -> str:
    return package[len(module) + 1 :] if package.startswith(module + "/") else package


def runs_of(inputs: list[Path]) -> list[list[Path]]:
    """The runs of the inputs: each directory is one run (its files, sorted),
    and the files named directly are one run together."""
    files = [path for path in inputs if not path.is_dir()]
    runs = [sorted(p for p in path.rglob("*") if p.is_file()) for path in inputs if path.is_dir()]
    return ([files] if files else []) + [run for run in runs if run]


WEIGH = {"slowest": max, "median": statistics.median}


def _weigh_runs(measured: list[dict[str, float]], weigh: str = "slowest") -> dict[str, float]:
    keys = sorted({key for one in measured for key in one})
    return {key: WEIGH[weigh](one[key] for one in measured if key in one) for key in keys}


def _go_run_times(files: list[Path], module: str) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
    """One run's package seconds (the shards of a package summed) and
    top-level test seconds (each test's share of its package wall time when
    its events carry a Time, else its Elapsed)."""
    tests: dict[str, dict[str, float]] = {}
    packages: dict[str, float] = {}
    for file in files:
        # One log or artifact at a time: a package's clock does not run
        # across the shards of two files.
        shares = TopLevelShares()
        timed: set[tuple[str, str]] = set()
        for event in _go_events([file]):
            package = event.get("Package", "")
            name = event.get("Test")
            action = event.get("Action")
            when = _event_time(event)
            shares.event(package, name, action, when)
            if name is not None and "/" not in name and action in ("run", "cont") and when is not None:
                timed.add((package, name))
            if action not in ("pass", "fail"):
                continue
            elapsed = float(event.get("Elapsed", 0))
            if name is None:
                # Shards of one package each report its elapsed time: sum them.
                packages[package] = packages.get(package, 0.0) + elapsed
            elif "/" not in name:
                share = shares.seconds(package, name)
                if (package, name) in timed and when is not None and share is not None:
                    elapsed = share
                timed.discard((package, name))
                tests.setdefault(_rel(package, module), {})[name] = elapsed
    return packages, tests


def go_timings(files: list[Path], module: str, runs: list[list[Path]] | None = None, weigh: str = "slowest") -> dict:
    """The recorded times of runs (default: files as one run), each package
    and test at the slowest (or median, weigh) run that timed it."""
    measured = [_go_run_times(run, module) for run in (runs or [files])]
    packages = _weigh_runs([one[0] for one in measured], weigh)
    rels = sorted({rel for one in measured for rel in one[1]})
    tests = {rel: _weigh_runs([one[1][rel] for one in measured if rel in one[1]], weigh) for rel in rels}
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


def python_timings(files: list[Path], runs: list[list[Path]] | None = None, weigh: str = "slowest") -> dict:
    """Each test file's seconds, at the slowest (or median, weigh) run (default: files as one run)."""
    seconds = _weigh_runs([_python_run_times(run) for run in (runs or [files])], weigh)
    return {"files": {path: round(value, 2) for path, value in sorted(seconds.items())}}


def _python_run_times(files: list[Path]) -> dict[str, float]:
    seconds: dict[str, float] = {}
    for file in files:
        for case in ET.parse(file).iter("testcase"):
            parts = (case.get("classname") or "").split(".")
            for end in range(len(parts), 0, -1):
                candidate = "/".join(parts[:end]) + ".py"
                if (ROOT / candidate).is_file():
                    seconds[candidate] = seconds.get(candidate, 0.0) + float(case.get("time") or 0)
                    break
    return seconds


# The Windows parts run one package at a time (-p=1), so every package also
# pays for linking its test binary, which its reported elapsed time leaves out.
WINDOWS_LINK_SECONDS = 6.0
# The packages Windows Native CI splits by test (go_test_shards.py test mode,
# and package mode for internal/hookpaths: its program sweep and archive table
# take about 20 minutes on a hosted runner, more than one shard step,
# GAP-0749). A package missing here loses its per-test times at a refresh and
# runs whole again.
WINDOWS_TEST_SHARDED = (
    "internal/gateway",
    "internal/gateway/connector",
    "internal/gateway/connector/hookexec",
    "internal/hookpaths",
)


def windows_go_timings(
    files: list[Path], module: str, runs: list[list[Path]] | None = None, weigh: str = "slowest"
) -> dict:
    runs = runs or [files]
    packages = _weigh_runs([_windows_package_times(run) for run in runs], weigh)
    # The test-level shards balance on their recorded test times.
    tests = {
        rel: names
        for rel, names in go_timings(files, module, runs, weigh)["tests"].items()
        if rel in WINDOWS_TEST_SHARDED
    }
    return {"packages": {package: round(value, 1) for package, value in sorted(packages.items())}, "tests": tests}


def _windows_package_times(files: list[Path]) -> dict[str, float]:
    pattern = re.compile(r"\[go-package-time\] (\S+) (?:pass|fail|skip) ([0-9.]+)")
    packages: dict[str, float] = {}
    for file in files:
        for match in pattern.finditer(file.read_text(encoding="utf-8", errors="replace")):
            # A package split into parts (internal/hookpaths) prints one line
            # per part, each with its own link: its weight is their sum, as
            # go_test_shards.py splits a package by its recorded weight.
            package = match.group(1)
            packages[package] = packages.get(package, 0.0) + float(match.group(2)) + WINDOWS_LINK_SECONDS
    return packages


def keep_unreached_go_tests(old: dict, new: dict, files: list[Path], module: str, root: Path = ROOT) -> dict:
    """new, with the recorded time of each test its package still defines
    that no input ran to an end. The -timeout that ends a shard leaves the
    tests it had not reached without an event; without their old time they
    would weigh as unlisted tests, and the next plan could put them together
    in one shard."""
    ended: dict[str, set[str]] = {}
    for event in _go_events(files):
        name = event.get("Test")
        if event.get("Action") in ("pass", "fail", "skip") and name and "/" not in name:
            ended.setdefault(_rel(event.get("Package", ""), module), set()).add(name)
    for rel, names in new.get("tests", {}).items():
        defined = set()
        for path in (root / rel).glob("*_test.go"):
            defined.update(TEST_FUNCTION_RE.findall(path.read_text(encoding="utf-8")))
        for name, seconds in old.get("tests", {}).get(rel, {}).items():
            if name in defined and name not in names and name not in ended.get(rel, set()):
                names[name] = seconds
        new["tests"][rel] = dict(sorted(names.items()))
    return new


def keep_unreached_windows_packages(old: dict, new: dict, module: str, root: Path = ROOT) -> dict:
    """new, with the recorded time of each package that still exists and
    that no input log gave a time. The step timeout that ends a Windows
    remaining-package part leaves the packages after it without a
    [go-package-time] line; without their old time they would weigh the
    median, and the next plan could put several of them in one part."""
    packages = dict(new.get("packages", {}))
    for package, seconds in old.get("packages", {}).items():
        if package not in packages and any((root / _rel(package, module)).glob("*.go")):
            packages[package] = seconds
    new["packages"] = dict(sorted(packages.items()))
    return new


def merge_go_timings(old: dict, new: dict, module: str) -> dict:
    """Recorded go timings with the packages new measured replaced: a
    package new has drops its old per-test times too, so a test it no longer
    records falls back to the new "*"."""
    packages = {**old.get("packages", {}), **new.get("packages", {})}
    prefix = module + "/"
    measured = {package.removeprefix(prefix) for package in new.get("packages", {})}
    tests = {rel: names for rel, names in old.get("tests", {}).items() if rel not in measured}
    tests.update(new.get("tests", {}))
    return {"packages": dict(sorted(packages.items())), "tests": dict(sorted(tests.items()))}


def prune_retired(data: dict, module: str, root: Path = ROOT) -> dict:
    """data without the packages this tree no longer has (no .go file in
    their folder) and without the tests a package no longer defines. A
    refresh that read a run of another branch, or kept an old entry with
    --update, would otherwise weigh code that is not here."""

    def defined(rel: str) -> set[str] | None:
        folder = root / rel
        if not any(folder.glob("*.go")):
            return None
        names: set[str] = set()
        for path in folder.glob("*_test.go"):
            names.update(TEST_FUNCTION_RE.findall(path.read_text(encoding="utf-8")))
        return names

    packages = {
        package: seconds
        for package, seconds in data.get("packages", {}).items()
        if defined(_rel(package, module)) is not None
    }
    tests: dict[str, dict[str, float]] = {}
    for rel, names in data.get("tests", {}).items():
        known = defined(rel)
        if known is None:
            continue
        tests[rel] = {name: seconds for name, seconds in names.items() if name == "*" or name in known}
    return {**data, "packages": dict(sorted(packages.items())), "tests": dict(sorted(tests.items()))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("kind", choices=("go", "python", "windows-go"))
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, help="output file (default: scripts/test-timings/<kind>.json)")
    parser.add_argument(
        "--update",
        action="store_true",
        help="go: replace only the packages the inputs measured and keep the rest of the output file",
    )
    parser.add_argument(
        "--weigh",
        choices=sorted(WEIGH),
        default="slowest",
        help="several runs: weigh each package or test by its slowest run (default) or the median run",
    )
    args = parser.parse_args()
    module = re.search(r"^module\s+(\S+)", (ROOT / "go.mod").read_text(encoding="utf-8"), re.MULTILINE).group(1)
    runs = runs_of(args.inputs)
    files = [file for run in runs for file in run]
    if args.kind == "go":
        data, default = go_timings(files, module, runs, args.weigh), "go-linux.json"
    elif args.kind == "python":
        data, default = python_timings(files, runs, args.weigh), "python-linux.json"
    else:
        data, default = windows_go_timings(files, module, runs, args.weigh), "go-windows.json"
    out = args.out or OUT_DIR / default
    if args.kind != "python" and out.is_file():
        old = json.loads(out.read_text(encoding="utf-8"))
        data = keep_unreached_go_tests(old, data, files, module)
        if args.kind == "windows-go":
            data = keep_unreached_windows_packages(old, data, module)
        if args.update:
            data = merge_go_timings(old, data, module)
    if args.kind != "python":
        data = prune_retired(data, module)
    _write(out, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
