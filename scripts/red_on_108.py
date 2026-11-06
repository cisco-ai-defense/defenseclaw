#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Replay mapped 1.0.9 fix tests on 1.0.8 and record behaviour-red evidence."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TEST_NAME = re.compile(r"\b(Test[A-Z][A-Za-z0-9_]*|test_[a-z0-9_]+)\b")
GAP = re.compile(r"\bGAP-\d{4}\b")


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()


def handoff_tests(handoff: Path, fallback: list[str]) -> list[str]:
    if not handoff.is_file():
        return fallback
    return sorted(set(TEST_NAME.findall(handoff.read_text(encoding="utf-8", errors="replace"))))


def tests_for_gap(tests: list[str], gap: str) -> list[str]:
    number = int(gap[-4:])
    forms = (
        f"GAP{number:04d}",
        f"GX{number:03d}",
        f"GX{number:04d}",
        f"G{number}",
        f"G{number:03d}",
        f"G{number:04d}",
        f"gap{number:04d}",
        f"g{number}",
    )
    return [name for name in tests if any(re.search(re.escape(form) + r"(?!\d)", name) for form in forms)]


def candidates(repo: Path, gap: str, base: str) -> list[tuple[str, list[str]]]:
    text = git(repo, "log", "--all", "--since=2026-11-03", "--format=%H%x09%s", "--grep=" + gap, "-i")
    result = []
    for line in text.splitlines():
        commit, _, subject = line.partition("\t")
        if gap not in subject.upper() or subject.lower().startswith(("revert(", "revert ")):
            continue
        if (
            subprocess.run(
                ["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, base],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ):
            continue
        files = git(repo, "diff-tree", "--no-commit-id", "--name-only", "--diff-filter=AM", "-r", commit).splitlines()
        test_files = [name for name in files if name.endswith("_test.go") or re.search(r"(?:^|/)test_[^/]+\.py$", name)]
        if test_files:
            result.append((commit, test_files))
    return result


def mapped_python_files(worktree: Path, files: list[str], tests: list[str]) -> list[str]:
    matched = []
    for name in files:
        if not name.startswith("cli/tests/") or not name.endswith(".py"):
            continue
        source = (worktree / name).read_text(encoding="utf-8", errors="replace")
        if any(
            re.search(r"^\s*(?:async\s+)?def\s+" + re.escape(test) + r"\s*\(", source, re.MULTILINE) for test in tests
        ):
            matched.append(name)
    return matched


def classify_test_result(command: list[str], returncode: int, output: str) -> str:
    if returncode == 0 or "[no tests to run]" in output:
        return "PASS_ON_108"
    # A pytest summary can say FAILED even when the named test never reached an
    # assertion. Treat dependency and collection failures as missing evidence.
    infrastructure = (
        "build failed",
        "undefined:",
        "syntaxerror",
        "importerror",
        "modulenotfounderror",
        "error collecting",
        "error at setup",
        "fixture '",
        "filenotfounderror",
        "no such file or directory",
        "file does not exist",
        "missing fixture",
    )
    if any(marker in output.lower() for marker in infrastructure):
        return "COMPILE_ONLY"
    if re.search(r"\b(?:setup|fixture|initialization|testmain)\b", output, re.IGNORECASE):
        return "COMPILE_ONLY"
    if "go" in command and "--- FAIL:" in output:
        # A Go FAIL marker also follows setup errors inside a test. A verdict
        # assertion must be emitted from a test source line, not a log message
        # from a helper or another package.
        assertions = (
            r"\bgot\b[^\n]{0,240}\bwant\b",
            r"\bwant\b[^\n]{0,240}\bgot\b",
            r"\bexpected\b[^\n]{0,240}\b(?:got|observed|actual)\b",
            r"\b(?:got|observed|actual)\b[^\n]{0,240}\bexpected\b",
        )
        for line in output.splitlines():
            match = re.match(r"^\s+[^\s:]+_test\.go:\d+:\s+(.+)$", line)
            if match and any(re.search(pattern, match.group(1), re.IGNORECASE) for pattern in assertions):
                return "BEHAVIOR_RED"
        return "UNCLASSIFIED_FAIL"
    if "pytest" in command and (
        "AssertionError" in output or "Failed: DID NOT RAISE" in output or re.search(r"(?m)^E\s+assert\b", output)
    ):
        return "BEHAVIOR_RED"
    return "UNCLASSIFIED_FAIL"


def overlay_go_fixtures(repo: Path, worktree: Path, commit: str, directory: str) -> None:
    """Use the test commit's package fixtures with the old product sources."""
    current = set(git(repo, "ls-tree", "-r", "--name-only", commit, "--", directory).splitlines())
    prior = set(git(worktree, "ls-tree", "-r", "--name-only", "HEAD", "--", directory).splitlines())
    fixture_dirs = {"testdata", "fixtures", "testfixtures", "test_fixtures", "golden", "goldens"}
    source_suffixes = {".go", ".py", ".sh", ".js", ".ts", ".ps1", ".c", ".h", ".s"}

    def fixture_root(name: str) -> Path | None:
        relative = Path(name).relative_to(directory)
        for index, part in enumerate(relative.parts[:-1]):
            if part in fixture_dirs:
                return Path(directory, *relative.parts[: index + 1])
        return None

    subpackages = {
        Path(name).parent
        for name in current | prior
        if name.endswith(".go") and Path(name).parent != Path(directory) and fixture_root(name) is None
    }

    def in_package(name: str) -> bool:
        path = Path(name)
        return not any(path.is_relative_to(package) for package in subpackages)

    current = {name for name in current if in_package(name)}
    prior = {name for name in prior if in_package(name)}

    # Rebuild every test-owned fixture tree, including deletions. New non-code
    # assets outside those conventional trees may also be test dependencies.
    for root in {root for name in current | prior if (root := fixture_root(name)) is not None}:
        path = worktree / root
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
    for name in sorted(current):
        if fixture_root(name) is None and Path(name).suffix in source_suffixes:
            continue
        target = worktree / name
        if not target.resolve(strict=False).is_relative_to(worktree.resolve()) or target.is_symlink():
            raise ValueError(f"fixture path escapes audit worktree: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{name}"]))


def run_one(repo: Path, worktree: Path, commit: str, files: list[str], tests: list[str], base: str) -> str:
    subprocess.run(["git", "-C", str(worktree), "reset", "--hard", base], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(worktree), "clean", "-fd"], check=True, stdout=subprocess.DEVNULL)
    for name in files:
        content = subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{name}"])
        target = worktree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    go_tests = [name for name in tests if name.startswith("Test")]
    py_tests = [name for name in tests if name.startswith("test_")]
    commands = []
    for directory in sorted({str(Path(name).parent) for name in files if name.endswith("_test.go")}):
        names = [
            name
            for name in go_tests
            if any(
                re.search(
                    r"\bfunc\s+" + re.escape(name) + r"\s*\(",
                    (worktree / path).read_text(encoding="utf-8", errors="replace"),
                )
                for path in files
                if str(Path(path).parent) == directory and path.endswith("_test.go")
            )
        ]
        if names:
            overlay_go_fixtures(repo, worktree, commit, directory)
            commands.append(
                [
                    "nice",
                    "-n",
                    "15",
                    "go",
                    "test",
                    "-p",
                    "4",
                    "-count=1",
                    "-timeout",
                    "12m",
                    "-run",
                    "^(?:" + "|".join(map(re.escape, names)) + ")$",
                    "./" + directory,
                ]
            )
    py_files = mapped_python_files(worktree, files, py_tests)
    if py_files and py_tests:
        commands.append([sys.executable, "-m", "pytest", "-q", "-k", " or ".join(py_tests), *py_files])
    if not commands:
        return "NO_MAPPED_TEST"
    statuses = []
    gate_env = os.environ.copy()
    gate_env["GOTOOLCHAIN"] = "go1.26.4"
    gate_env.setdefault("GOMAXPROCS", "8")
    for command in commands:
        try:
            run = subprocess.run(
                command,
                cwd=worktree,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=780,
                env=gate_env,
            )
        except subprocess.TimeoutExpired:
            statuses.append("TIMEOUT")
            continue
        output = run.stdout
        statuses.append(classify_test_result(command, run.returncode, output))
    if "BEHAVIOR_RED" in statuses and all(s == "BEHAVIOR_RED" for s in statuses):
        return "BEHAVIOR_RED"
    if "COMPILE_ONLY" in statuses:
        return "COMPILE_ONLY"
    if "TIMEOUT" in statuses:
        return "TIMEOUT"
    if "UNCLASSIFIED_FAIL" in statuses:
        return "UNCLASSIFIED_FAIL"
    return "PASS_ON_108"


def run_mapped_candidate(
    repo: Path, worktree: Path, found: list[tuple[str, list[str]]], tests: list[str], base: str
) -> tuple[str, str]:
    for commit, files in found:
        status = run_one(repo, worktree, commit, files, tests, base)
        if status != "NO_MAPPED_TEST":
            return commit, status
    return "-", "NO_MAPPED_TEST"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--handoffs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base", default="1.0.8")
    parser.add_argument("--only", action="append", help="Limit to a pod key or gap ID")
    args = parser.parse_args()
    repo = Path.cwd()
    base = git(repo, "rev-parse", args.base + "^{commit}")
    mapping = json.loads(args.map.read_text(encoding="utf-8"))
    rows = []
    with tempfile.TemporaryDirectory(prefix="red-on-108-") as temporary:
        worktree = Path(temporary) / "base"
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach", str(worktree), base],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        try:
            for pod, entry in sorted(mapping.items()):
                tests = handoff_tests(args.handoffs / f"IN-r109-{pod}.md", entry.get("tests", []))
                for gap in entry.get("gaps", []):
                    if args.only and pod not in args.only and gap not in args.only:
                        continue
                    if not GAP.fullmatch(gap):
                        rows.append((pod, gap, "-", "INVALID_GAP", "-"))
                        continue
                    gap_tests = tests_for_gap(tests, gap)
                    if len(entry.get("gaps", [])) == 1:
                        gap_tests = entry.get("tests", [])
                    found = candidates(repo, gap, base)
                    if not gap_tests:
                        rows.append((pod, gap, "-", "NO_GAP_SELECTOR", "-"))
                    elif not found:
                        rows.append((pod, gap, "-", "COMMIT_UNRESOLVED", ",".join(gap_tests)))
                    else:
                        commit, status = run_mapped_candidate(repo, worktree, found, gap_tests, base)
                        rows.append((pod, gap, commit[:12] if commit != "-" else "-", status, ",".join(gap_tests)))
                    print(f"{pod} {gap} {rows[-1][3]}", flush=True)
        finally:
            subprocess.run(
                ["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)],
                check=True,
                stdout=subprocess.DEVNULL,
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t")
        writer.writerow(("pod", "gap", "commit", "status", "tests"))
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.output}")
    return 0 if rows and all(row[3] == "BEHAVIOR_RED" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
