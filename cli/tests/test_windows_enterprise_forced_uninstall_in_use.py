# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1474: a forced Setup /uninstall that cannot move StateRoot aside.

Another program's open file under StateRoot fails the move. The refusal named
the raw .NET Move exception ("Access to the path ... is denied") and no next
step. It now says a file inside StateRoot is in use and to run FORCE=1 again.
The native in-use leg is in enterprise-standalone-purge-bundle-lock-smoke.ps1;
this portable leg makes the move fail with a read-only parent folder.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"

HARNESS = r"""
param([string]$ModulePath, [string]$StateRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$null, [ref]$errors)
if ($errors.Count -gt 0) { throw $errors[0].Message }
foreach ($name in @('Invoke-DefenseClawForcedUninstallPreparation', 'ConvertTo-DefenseClawBoundedDiagnostic')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
function Get-DefenseClawEnumeratorServiceName { param($GuardianServiceName) 'enumerator' }
function Assert-DefenseClawOwnedServiceOrAbsent { }
function Get-DefenseClawSensorHelperImage { param($Layout, $GatewayServiceName) '' }
function Test-DefenseClawServiceExists { param($Name) $false }
function Assert-DefenseClawNoReparsePath { param($Path) }
function Exit-DefenseClawPurgeBundleLock { }
function Restore-DefenseClawForcedUninstallPreparation { param($Preparation) return @() }
$layout = @{ StateRoot = $StateRoot; GatewayPath = 'gateway'; ManifestPath = 'manifest';
    SensorHelperServiceName = 'helper'; SensorHelperPath = 'helper.exe' }
try {
    [void](Invoke-DefenseClawForcedUninstallPreparation -Layout $layout -GatewayServiceName gateway -GuardianServiceName guardian)
    'MOVED'
}
catch { 'REFUSED: ' + $_.Exception.Message }
"""


def _pwsh() -> str | None:
    return os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")


@pytest.mark.skipif(sys.platform == "win32", reason="the native leg is the Windows smoke")
def test_forced_uninstall_says_a_file_in_state_root_is_in_use(tmp_path: Path) -> None:
    engine = _pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    if os.geteuid() == 0:
        pytest.skip("root ignores the read-only parent that makes the move fail")
    parent = tmp_path / "ProgramData"
    state_root = parent / "DefenseClaw"
    state_root.mkdir(parents=True)
    (state_root / "held.txt").write_text("held", encoding="utf-8")
    harness = tmp_path / "forced-uninstall-in-use.ps1"
    harness.write_text(HARNESS, encoding="utf-8")
    parent.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        completed = subprocess.run(
            [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
             "-ModulePath", str(MODULE), "-StateRoot", str(state_root)],
            capture_output=True, text=True, timeout=120, check=False,
        )
    finally:
        parent.chmod(stat.S_IRWXU)
    output = completed.stdout.strip()
    assert completed.returncode == 0, completed.stderr
    assert output.startswith("REFUSED: "), output
    assert f"could not move StateRoot {state_root} aside" in output, output
    assert "a file or folder inside it is in use by another program" in output, output
    assert "run Setup /uninstall FORCE=1 again" in output, output
    assert "Exception calling" not in output, output
    assert state_root.is_dir()
