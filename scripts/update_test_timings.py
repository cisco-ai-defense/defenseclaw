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
         The darwin connector parts of Unix Standalone Lifecycle upload
         go-test-timings-darwin-connector-* the same way; --update keeps
         the other packages of go-darwin.json (internal/enterpriseunix):
           gh run download <run> --pattern 'go-test-timings-darwin-*' --dir t
           scripts/update_test_timings.py go t/*/*.json --update --out scripts/test-timings/go-darwin.json
  python pytest --junitxml reports of the Python suite -> python-linux.json
           pytest cli/tests --junitxml=py.xml ...; scripts/update_test_timings.py python py.xml
         Windows Native CI uploads windows-python-junit-<n> reports:
           scripts/update_test_timings.py python junit-windows-*.xml --out scripts/test-timings/python-windows.json
  windows-go  Windows Native CI job logs of the windows-go parts -> go-windows.json:
         package times from the packages parts ("[go-package-time] <package>
         <result> <seconds>") and the gateway and connector test times from
         the go test -json events the gw parts print
           gh run view <run> --log > win.log; scripts/update_test_timings.py windows-go win.log
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
            # A CI log puts a timestamp (and gh run view the job and step
            # names) before each event.
            start = line.find('{"')
            if start < 0:
                continue
            try:
                event = json.loads(line[start:])
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
# The packages Windows Native CI splits by test (go_test_shards.py test mode).
WINDOWS_TEST_SHARDED = ("internal/gateway", "internal/gateway/connector")


def windows_go_timings(files: list[Path], module: str) -> dict:
    pattern = re.compile(r"\[go-package-time\] (\S+) (?:pass|fail|skip) ([0-9.]+)")
    packages: dict[str, float] = {}
    for file in files:
        for match in pattern.finditer(file.read_text(encoding="utf-8", errors="replace")):
            packages[match.group(1)] = float(match.group(2)) + WINDOWS_LINK_SECONDS
    # The gateway and connector shards balance on their test times.
    tests = {rel: names for rel, names in go_timings(files, module)["tests"].items() if rel in WINDOWS_TEST_SHARDED}
    return {"packages": {package: round(value, 1) for package, value in sorted(packages.items())}, "tests": tests}


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
    args = parser.parse_args()
    module = re.search(r"^module\s+(\S+)", (ROOT / "go.mod").read_text(encoding="utf-8"), re.MULTILINE).group(1)
    if args.kind == "go":
        data, default = go_timings(args.inputs, module), "go-linux.json"
    elif args.kind == "python":
        data, default = python_timings(args.inputs), "python-linux.json"
    else:
        data, default = windows_go_timings(args.inputs, module), "go-windows.json"
    out = args.out or OUT_DIR / default
    if args.update and out.is_file():
        data = merge_go_timings(json.loads(out.read_text(encoding="utf-8")), data, module)
    _write(out, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
