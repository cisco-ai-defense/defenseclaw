# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Lifecycle diagnostics and rollback contracts checked from module helpers.

- A failed service start names SCM's exit codes, including the dependency's.
- A rollback accepts a restored guardian whose fresh reconcile has failed
  targets, and nothing else that is not ok.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "packaging" / "windows" / "tests"
SMOKES = {
    "enterprise-service-start-diagnostics-smoke.ps1": "service start diagnostics smoke passed",
    "enterprise-degraded-guardian-rollback-smoke.ps1": "degraded guardian rollback smoke passed",
}


def _engines() -> list[str]:
    # The smoke loads two string helpers by AST and never imports the module,
    # so it also runs under pwsh off Windows.
    found: list[str] = []
    for name in ("powershell.exe", "pwsh.exe", "pwsh"):
        path = shutil.which(name)
        if path and os.path.normcase(path) not in {os.path.normcase(p) for p in found}:
            found.append(path)
    if not found and os.name == "nt":
        return ["<no-powershell-engine-found>"]
    return found


@pytest.mark.parametrize("smoke", sorted(SMOKES))
@pytest.mark.parametrize("engine", _engines())
def test_lifecycle_helper_smoke(engine: str, smoke: str) -> None:
    assert Path(engine).is_file(), "no PowerShell engine found on a Windows runner"
    result = subprocess.run(
        [engine, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(TESTS / smoke)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert SMOKES[smoke] in result.stdout
