# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Lifecycle diagnostics and rollback contracts checked from module helpers.

- A failed service start names SCM's exit codes, including the dependency's.
- A rollback accepts a restored guardian whose fresh reconcile has failed
  targets, and nothing else that is not ok.
- A fresh Install's skipped busy profiles are validated and recorded.
- Permission drift is judged by write authority, and repairs, acceptances
  and recoveries are logged in the format the Go components share.
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
    "enterprise-target-runtime-skip-smoke.ps1": "target runtime skip smoke passed",
    "enterprise-resilience-helpers-smoke.ps1": "resilience helpers smoke passed",
    "enterprise-nuclear-user-data-paths-smoke.ps1": "nuclear user data paths smoke passed",
    "enterprise-installer-resilience-smoke.ps1": "installer resilience smoke passed",
    "enterprise-restart-delete-cancel-smoke.ps1": "restart delete cancel smoke passed",
}


def _engines() -> list[str]:
    # The smoke loads two string helpers by AST and never imports the module,
    # so it also runs under pwsh off Windows.
    if os.name == "nt":
        # The machine-wide engines, not PATH: a runner can omit them from PATH
        # or resolve a WindowsApps alias that fails before the script starts.
        from tests.test_windows_enterprise_service_contract import windows_powershell_engines

        return windows_powershell_engines() or ["<no-powershell-engine-found>"]
    found: list[str] = []
    for name in ("powershell.exe", "pwsh.exe", "pwsh"):
        path = shutil.which(name)
        if path and os.path.normcase(path) not in {os.path.normcase(p) for p in found}:
            found.append(path)
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
