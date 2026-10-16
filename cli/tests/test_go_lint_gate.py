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


def test_go_lint_runs_vet_then_golangci_lint() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    recipe = makefile[makefile.index("\ngo-lint: ") : makefile.index("\ngo-lint-analyzers:")]
    assert recipe.index("go vet ./...") < recipe.index("$(MAKE) --no-print-directory go-lint-analyzers")


def test_ci_go_lint_has_the_history_for_changed_lines() -> None:
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = ci["jobs"]["go-lint"]["steps"]
    checkout = next(step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0
    lint = next(step for step in steps if step.get("run") == "make go-lint")
    assert lint["env"] == {"GOLANGCI_LINT_BASE": "origin/${{ github.base_ref || 'main' }}"}


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
