# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Local checks for the macOS App workflow and its generated command table.

The workflow decides in one job (Detect macOS app changes) whether the
expensive macOS validation runs, and another job (macOS App Required) turns
the answer and the job results into the one required status. A value the
second job does not handle, or a generated file that has drifted from its
source, used to show up only on a hosted macOS runner. These tests run the
same shell and the same generator check on any machine.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/macos-app.yml"

pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the workflow shell runs under bash",
)


def _steps(job: str) -> list[dict]:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return document["jobs"][job]["steps"]


def _run_text(job: str, step_name: str) -> str:
    for step in _steps(job):
        if step.get("name") == step_name:
            return step["run"]
    raise AssertionError(f"{job}: no step named {step_name!r}")


def _required(*, changed: str, changes: str = "success", license_headers: str = "success", build: str = "success"):
    script = _run_text("macos-app-required", "Require every macOS app check")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "CHANGES_RESULT": changes,
        "MACOS_CHANGED": changed,
        "LICENSE_HEADERS_RESULT": license_headers,
        "BUILD_AND_TEST_RESULT": build,
    }
    return subprocess.run(
        ["bash", "-e", "-c", script], env=env, capture_output=True, text=True, check=False
    )


def test_detect_job_only_writes_values_the_required_job_handles() -> None:
    detect = _run_text("changes", "Select macOS app validation")
    written = set(re.findall(r'echo "macos=([^"]*)" >> "\$GITHUB_OUTPUT"', detect))
    assert written, "the detect step writes no macos= output"
    required = _run_text("macos-app-required", "Require every macOS app check")
    handled = set(re.findall(r"^\s*([A-Za-z0-9_]+)\)\s*$", required, flags=re.MULTILINE)) - {"esac"}
    assert written <= handled, (
        f"Detect macOS app changes can write {sorted(written)} but macOS App Required handles "
        f"{sorted(handled)}: add the new value to the case in macOS App Required"
    )


@pytest.mark.parametrize(
    ("changed", "license_headers", "build", "want"),
    [
        ("true", "success", "success", 0),
        ("true", "success", "failure", 1),
        ("true", "failure", "success", 1),
        ("true", "skipped", "skipped", 1),
        ("false", "skipped", "skipped", 0),
        ("false", "success", "success", 1),
    ],
)
def test_required_job_decisions(changed: str, license_headers: str, build: str, want: int) -> None:
    result = _required(changed=changed, license_headers=license_headers, build=build)
    assert result.returncode == want, result.stdout + result.stderr


def test_required_job_fails_loudly_on_an_unhandled_decision() -> None:
    result = _required(changed="maybe", license_headers="skipped", build="skipped")
    assert result.returncode == 1
    assert "unexpected macOS app path decision: maybe" in result.stdout


def test_required_job_fails_when_the_detect_job_failed() -> None:
    result = _required(changed="", changes="failure", license_headers="skipped", build="skipped")
    assert result.returncode != 0


def test_macos_command_table_matches_the_tui_registry() -> None:
    """Generated macos/.../CommandRegistry.swift must match registry_data.py.

    The macOS runner runs the same check inside make macos-app-test-scripts;
    a branch that adds a palette row to the TUI registry (a Substrate or CLI
    change) must regenerate the Swift table with
    python3 scripts/sync-macos-command-registry.py, or this fails here first.
    """
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/sync-macos-command-registry.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        "macOS CommandRegistry.swift is out of date with cli/defenseclaw/tui/registry_data.py; "
        "run: python3 scripts/sync-macos-command-registry.py\n" + result.stdout + result.stderr
    )
