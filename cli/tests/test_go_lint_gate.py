# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""`make go-lint` runs the pinned golangci-lint (#1228).

Before, a missing golangci-lint (exit 127) silently fell back to `go vet`, so
CI, which never installed golangci-lint, ran only vet, and the bootstrap
installed v2.11.0, which does not support the current Go toolchain. Now the
Makefile runs the pinned version itself, a missing linter fails the gate, and
only the documented toolchain mismatch skips golangci-lint (vet still runs).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
INSTALL_DEV = ROOT / "scripts" / "install-dev.sh"
PIN = "v2.14.0"


def _makefile_pin() -> str:
    match = re.search(r"^GOLANGCI_LINT_VERSION := (\S+)$", MAKEFILE.read_text(encoding="utf-8"), re.M)
    assert match, "Makefile has no GOLANGCI_LINT_VERSION"
    return match.group(1)


def test_bootstrap_and_makefile_pin_the_same_golangci_lint() -> None:
    assert _makefile_pin() == PIN
    text = INSTALL_DEV.read_text(encoding="utf-8")
    assert f'readonly GOLANGCI_LINT_VERSION="{PIN}"' in text
    assert 'golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"' in text
    assert re.search(r"golangci-lint@v\d", text) is None, "install-dev.sh hard-codes a second golangci-lint version"
    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert (
        "GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"
        in makefile
    )
    # The stale-PATH lookup is gone.
    assert 'PATH="$(GOBIN):$(PATH)" golangci-lint' not in makefile


def _recipe(makefile: str, target: str) -> str:
    start = makefile.index(f"\n{target}: ") + 1
    end = makefile.find("\n\n", start)
    return makefile[start:end]


def test_go_lint_runs_vet_then_golangci_lint() -> None:
    # make go-lint is go-vet (gofmt and go vet), then golangci-lint. CI runs
    # the two halves as sibling jobs behind the Go Lint check.
    makefile = MAKEFILE.read_text(encoding="utf-8")
    lint = _recipe(makefile, "go-lint")
    assert lint.splitlines() == ["go-lint: go-vet", "\t@$(MAKE) --no-print-directory go-lint-analyzers"]
    vet = _recipe(makefile, "go-vet")
    assert vet.startswith("go-vet: sync-openclaw-extension\n")
    assert vet.index("gofmt -l") < vet.index("go vet ./...")
    assert "go-lint-analyzers" not in vet


def test_go_lint_vets_the_openshell_integration_tag() -> None:
    # The live Claude Code run-config test sits behind the openshell_integration
    # build tag, so a plain `go vet ./...` never compiles it (GAP-0280).
    vet = _recipe(MAKEFILE.read_text(encoding="utf-8"), "go-vet")
    tagged = "go vet -tags openshell_integration ./internal/openshell/image/"
    assert vet.index("go vet ./...") < vet.index(tagged)


def test_ci_go_lint_has_the_history_for_changed_lines() -> None:
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job = ci["jobs"]["go-lint-analyzers"]
    assert job["timeout-minutes"] == 20
    steps = job["steps"]
    checkout = next(step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == "${{ github.event_name == 'pull_request' && 2 || 0 }}"
    assert checkout["with"]["persist-credentials"] is False
    # golangci-lint type-checks the tree make go-lint syncs first.
    assert any(step.get("run") == "make plugin sync-openclaw-extension" for step in steps)
    lint = next(step for step in steps if step.get("name") == "Go lint (golangci-lint on changed lines)")
    # The Makefile's own recipe with its pinned golangci-lint (installed into
    # the restored cache directory).
    assert 'make go-lint-analyzers GOLANGCI_LINT="$bin"' in lint["run"]
    assert lint["env"] == {
        "GOLANGCI_LINT_BASE": "${{ github.event_name == 'pull_request' && 'HEAD^1' || 'origin/main' }}",
        "GOLANGCI_DIR": "${{ steps.golangci.outputs.dir }}",
        "GOLANGCI_VERSION": "${{ steps.golangci.outputs.version }}",
    }


def test_ci_go_lint_is_go_vet_and_golangci_lint_behind_one_check() -> None:
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    jobs = ci["jobs"]
    vet = jobs["go-vet"]
    assert [step.get("run") for step in vet["steps"] if step.get("run")] == [
        "make plugin",
        "make amp-plugin-typecheck",
        "make go-vet",
    ]
    for job_id in ("go-vet", "go-lint-analyzers"):
        assert jobs[job_id]["if"] == "${{ !cancelled() && needs.changes.outputs.go != 'false' }}", job_id
    aggregate = jobs["go-lint"]
    assert aggregate["name"] == "Go Lint"
    assert aggregate["if"] == "${{ always() }}"
    assert aggregate["needs"] == ["changes", "go-vet", "go-lint-analyzers"]
    assert "steps" in aggregate and len(aggregate["steps"]) == 1
    run = aggregate["steps"][0]["run"]
    # Skips pass only when the classifier skipped Go; otherwise both must pass.
    assert '[ "$GO_SUITE" = false ] && [ "$VET_RESULT" = skipped ] && [ "$ANALYZERS_RESULT" = skipped ]' in run
    assert 'test "$VET_RESULT" = success' in run and 'test "$ANALYZERS_RESULT" = success' in run


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="runs the aggregate step with bash")
@pytest.mark.parametrize(
    ("results", "go_suite", "passes"),
    [
        (("success", "success"), "true", True),
        (("skipped", "skipped"), "false", True),
        (("skipped", "skipped"), "true", False),
        (("success", "failure"), "true", False),
        (("failure", "success"), "true", False),
        (("success", "skipped"), "false", False),
        (("cancelled", "success"), "true", False),
    ],
)
def test_ci_go_lint_aggregate_verdicts(results: tuple[str, str], go_suite: str, passes: bool) -> None:
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    run = ci["jobs"]["go-lint"]["steps"][0]["run"]
    env = {**os.environ, "GO_SUITE": go_suite, "VET_RESULT": results[0], "ANALYZERS_RESULT": results[1]}
    proc = subprocess.run(["bash", "-c", run], env=env, capture_output=True, text=True, timeout=30, check=False)
    assert (proc.returncode == 0) is passes, proc.stdout + proc.stderr


needs_make = pytest.mark.skipif(
    os.name == "nt" or shutil.which("make") is None or shutil.which("git") is None,
    reason="runs the Makefile recipe with a POSIX shell",
)


def _head() -> str:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip("not a git checkout")
    return proc.stdout.strip()


def _run(tmp_path: Path, body: str, base: str) -> tuple[subprocess.CompletedProcess[str], str]:
    fake = tmp_path / "golangci-lint"
    argv = tmp_path / "argv"
    fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" > "{argv}"\n{body}\n', encoding="utf-8")
    fake.chmod(0o755)
    proc = subprocess.run(
        [
            "make",
            "-s",
            "--no-print-directory",
            "go-lint-analyzers",
            f"GOLANGCI_LINT={fake}",
            f"GOLANGCI_LINT_BASE={base}",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc, argv.read_text(encoding="utf-8").strip() if argv.exists() else ""


@needs_make
def test_lints_only_lines_changed_since_the_merge_base(tmp_path: Path) -> None:
    head = _head()
    proc, argv = _run(tmp_path, "exit 0", "HEAD")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert argv == f"run --new-from-rev={head}"


@needs_make
def test_an_empty_base_lints_the_whole_tree(tmp_path: Path) -> None:
    _head()
    proc, argv = _run(tmp_path, "exit 0", "")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert argv == "run"


@needs_make
def test_a_missing_base_fails_with_a_hint(tmp_path: Path) -> None:
    _head()
    proc, argv = _run(tmp_path, "exit 0", "refs/heads/fg15-no-such-branch")
    assert proc.returncode != 0
    assert "no merge base with refs/heads/fg15-no-such-branch" in proc.stdout + proc.stderr
    assert argv == ""


@needs_make
def test_a_missing_linter_fails_instead_of_falling_back(tmp_path: Path) -> None:
    _head()
    proc, _ = _run(tmp_path, 'echo "golangci-lint: not found" >&2; exit 127', "")
    assert proc.returncode != 0
    assert "falling back" not in proc.stdout + proc.stderr
    assert "does not support this Go toolchain" not in proc.stdout + proc.stderr


@needs_make
def test_lint_findings_fail_the_gate(tmp_path: Path) -> None:
    _head()
    proc, _ = _run(tmp_path, 'echo "x.go:1:1: func f is unused (unused)"; echo "1 issues:"; exit 1', "")
    assert proc.returncode != 0
    assert "func f is unused" in proc.stdout


@needs_make
@pytest.mark.parametrize(
    "message",
    [
        "can't load config: the Go language version (go1.26) used to build golangci-lint is lower than the targeted Go version (1.27)",
        "x/tools: package requires newer Go version go1.28 (application built with go1.27)",
    ],
)
def test_only_the_documented_toolchain_mismatch_is_skipped(tmp_path: Path, message: str) -> None:
    _head()
    proc, _ = _run(tmp_path, f'echo "{message}" >&2; exit 3', "")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "does not support this Go toolchain yet" in proc.stdout
