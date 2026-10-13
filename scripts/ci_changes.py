#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Choose the CI suites a pull request needs from the files it changes.

ci.yml, windows-native.yml and connector-live-e2e.yml call this from a small
"changes" job. Every event other than pull_request (push to main, schedule,
workflow_dispatch, release tags) runs everything. A pull request runs only the
suites its files feed, plus the tests that read a changed file by name:

* A Python test that names a changed file runs even when no Python changed.
  A docs, workflow or script change therefore runs the tests that pin it.
* A Go test that names a changed non-Go file runs alone in "Go Pinned Tests".
* A script or Makefile that names a changed file runs the parity checks.
* A PowerShell harness that names a changed file runs the PowerShell job.

Unknown paths, large pull requests and any git failure run everything.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Pull requests above this many files run everything.
LARGE_PR_FILES = 300

# Suite flags. docs and macos_app are informational: ci.yml runs nothing for
# them, docs-site.yml and macos-app.yml keep their own path gates.
SUITES = (
    "go",
    "python",
    "tui",
    "ts",
    "rego",
    "windows",
    "packaging",
    "checks",
    "pwsh",
    "workflows",
)
EVERYTHING = frozenset(SUITES)

# First match wins. A pattern ending in "/" is a directory prefix; any other
# pattern is an fnmatch glob over the whole path, where "*" also crosses "/".
RULES: tuple[tuple[tuple[str, ...], frozenset[str]], ...] = (
    ((".github/workflows/", ".github/actionlint.yaml"), frozenset({"workflows"})),
    ((".github/",), frozenset()),
    (("docs-site/", "docs/"), frozenset({"docs"})),
    (("*.md", "*.mdx"), frozenset({"docs"})),
    (("macos/",), frozenset({"macos_app"})),
    (("third_party/",), frozenset({"go"})),
    # The enterprise lifecycle, its result contract and the v9 config
    # migration are what the enterprise install and upgrade lanes exercise.
    (
        (
            "internal/enterpriseunix/",
            "internal/enterprisestatus/",
            "internal/managed/",
            "internal/config/migrate_v9.go",
        ),
        frozenset({"go", "packaging"}),
    ),
    (("*.go", "go.mod", "go.sum"), frozenset({"go"})),
    (("cli/defenseclaw/tui/", "cli/tests/tui/"), frozenset({"tui"})),
    (
        (
            "cli/",
            "pyproject.toml",
            "uv.lock",
            "setup.py",
            "MANIFEST.in",
            "packages/",
            "skills/",
            "benchmarks/",
        ),
        frozenset({"python"}),
    ),
    (("extensions/",), frozenset({"ts", "go", "python"})),
    (("policies/",), frozenset({"rego", "go", "python"})),
    (("schemas/",), frozenset({"go", "python", "checks"})),
    (("bundles/",), frozenset({"go", "python"})),
    (
        ("internal/", "cmd/", "test/", "proto/", "plugins/", "testdata/", ".golangci.yml"),
        frozenset({"go"}),
    ),
    (
        ("packaging/windows/", "scripts/*.ps1", "scripts/*.psm1", "scripts/*.cs", "scripts/*windows*"),
        frozenset({"windows", "pwsh"}),
    ),
    (("packaging/",), frozenset({"packaging"})),
    ((".goreleaser.yaml", "release/"), frozenset({"packaging", "windows"})),
    # The Unix connector harness: connector-live-e2e.yml selects its full
    # matrix for it and the tests that pin it run through references.
    (("scripts/live-connector-e2e/",), frozenset({"connector"})),
    (("scripts/",), frozenset({"go", "python", "packaging", "checks"})),
    (("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"), frozenset({"packaging"})),
    ((".claude/", ".agents/", ".devin/"), frozenset()),
)

PY_TEST_ROOT = "cli/tests"
# This file and its test name many paths as data; they never pin them.
SELF = "scripts/ci_changes.py"
SELF_TEST = "cli/tests/test_ci_changes.py"
GO_TEST_FUNCTION_RE = re.compile(r"^func\s+(Test[A-Za-z0-9_]*)\s*\(", re.MULTILINE)
TUI_TEST_MARKER = "defenseclaw.tui"

# references(needles, pathspecs) -> repo-relative files whose text contains
# any needle as a fixed string.
References = Callable[[Iterable[str], Iterable[str]], list[str]]


def _matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return path.startswith(pattern)
    return fnmatch.fnmatchcase(path, pattern)


def suites_for(path: str) -> frozenset[str] | None:
    """Return the suite flags one path feeds, or None when the path is unknown."""

    for patterns, flags in RULES:
        if any(_matches(path, pattern) for pattern in patterns):
            return flags
    return None


def git_references(needles: Iterable[str], pathspecs: Iterable[str]) -> list[str]:
    needles = sorted(set(needles))
    if not needles:
        return []
    args = ["git", "grep", "-l", "-F", "-I"]
    for needle in needles:
        args += ["-e", needle]
    args += ["--", *pathspecs]
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git grep failed: {result.stderr.strip()}")
    return sorted(line for line in result.stdout.splitlines() if line)


def _go_test_targets(test_files: Iterable[str], read: Callable[[str], str]) -> list[dict[str, str]]:
    """Group the Test functions of *test_files* into one go test run per package."""

    by_package: dict[str, set[str]] = {}
    whole_package: set[str] = set()
    for path in test_files:
        package = "./" + path.rsplit("/", 1)[0] if "/" in path else "."
        names = GO_TEST_FUNCTION_RE.findall(read(path))
        if names:
            by_package.setdefault(package, set()).update(names)
        else:
            # A helper file with no tests of its own: run its whole package.
            whole_package.add(package)
    targets = []
    for package in sorted(set(by_package) | whole_package):
        if package in whole_package:
            run = "."
        else:
            run = "^(" + "|".join(sorted(by_package[package])) + ")$"
        targets.append({"package": package, "run": run})
    return targets


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8", errors="replace")


def everything(reason: str) -> dict[str, object]:
    return _outputs(set(EVERYTHING), [], [], reason)


def classify(
    files: list[str],
    references: References = git_references,
    read: Callable[[str], str] = _read,
) -> dict[str, object]:
    """Return the CI outputs for a pull request that changes *files*."""

    files = sorted({path for path in files if path})
    if not files:
        return everything("no changed files could be listed")
    if len(files) > LARGE_PR_FILES:
        return everything(f"{len(files)} changed files (more than {LARGE_PR_FILES})")

    flags: set[str] = set()
    unknown = []
    for path in files:
        suites = suites_for(path)
        if suites is None:
            unknown.append(path)
        else:
            flags |= suites
    if unknown:
        return everything("unclassified path: " + ", ".join(unknown[:5]))

    basenames = {path.rsplit("/", 1)[-1] for path in files}
    py_tests = []
    if "python" not in flags:
        py_tests = references(basenames, [f"{PY_TEST_ROOT}/*.py", f":!{SELF_TEST}"])
        if "tui" in flags:
            py_tests = sorted(
                set(py_tests)
                | set(references(["def test"], [f"{PY_TEST_ROOT}/tui/"]))
                | set(references([TUI_TEST_MARKER], [f"{PY_TEST_ROOT}/*.py", f":!{SELF_TEST}"]))
            )
        py_tests = [path for path in py_tests if _is_test_module(path)]

    go_tests: list[dict[str, str]] = []
    if "go" not in flags:
        non_go = {path.rsplit("/", 1)[-1] for path in files if "go" not in (suites_for(path) or set())}
        pinned = [
            path
            for path in references(non_go, ["*_test.go"])
            if not path.startswith("third_party/")
        ]
        go_tests = _go_test_targets(pinned, read)

    if "checks" not in flags and references(basenames, ["scripts/*.py", "scripts/*.sh", "Makefile", f":!{SELF}"]):
        flags.add("checks")
    if "pwsh" not in flags and references(basenames, ["scripts/*.ps1"]):
        flags.add("pwsh")

    return _outputs(flags, py_tests, go_tests, "pull request paths")


def _is_test_module(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return path.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _outputs(
    flags: set[str], py_tests: list[str], go_tests: list[dict[str, str]], reason: str
) -> dict[str, object]:
    def on(*names: str) -> bool:
        return any(name in flags for name in names)

    go = on("go")
    python = on("python")
    outputs: dict[str, object] = {name: name in flags for name in SUITES}
    outputs.update(
        {
            "docs": "docs" in flags,
            # Python Test shards: the full suite, or only the selected modules.
            "python_tests": python or bool(py_tests),
            "py_select": "" if python else " ".join(py_tests),
            "python_lint": on("python", "tui"),
            "wheel": on("python", "tui"),
            "go_pinned": not go and bool(go_tests),
            "core": go or python,
            "go_tests": json.dumps(go_tests, separators=(",", ":")),
            "checks": on("go", "python", "ts", "checks"),
            "install": on("go", "python", "packaging", "windows"),
            "enterprise": on("go", "packaging", "windows"),
            "windows_go": on("go", "windows"),
            "windows_python": on("python", "windows"),
            "windows_pkg": on("go", "python", "ts", "windows"),
            "pwsh": on("go", "python", "ts", "windows", "pwsh"),
            "code": on("go", "python", "tui", "ts", "rego", "windows", "packaging"),
            "reason": reason,
        }
    )
    return outputs


def changed_files(base: str, head: str) -> list[str] | None:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", base, head],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.splitlines()


def _render(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event", required=True, help="github.event_name")
    parser.add_argument(
        "--base",
        default="HEAD^1",
        help="pull request base; the default is the first parent of the PR merge commit",
    )
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--files-from", help="read changed paths from this file ('-' for stdin) instead of git")
    parser.add_argument("--github-output", help="append key=value lines to this file (GITHUB_OUTPUT)")
    parser.add_argument("--get", help="print only this output")
    args = parser.parse_args(argv)

    if args.event != "pull_request":
        outputs = everything(f"{args.event} event")
    else:
        if args.files_from == "-":
            files: list[str] | None = sys.stdin.read().splitlines()
        elif args.files_from:
            files = Path(args.files_from).read_text(encoding="utf-8").splitlines()
        else:
            files = changed_files(args.base, args.head)
        if files is None:
            outputs = everything("git diff failed")
        else:
            try:
                outputs = classify(files)
            except (OSError, RuntimeError) as exc:
                outputs = everything(f"classifier error: {exc}")

    if args.get:
        print(_render(outputs[args.get]))
        return 0
    lines = [f"{key}={_render(value)}" for key, value in outputs.items()]
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
