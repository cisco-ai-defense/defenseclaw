# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1750: a standalone fresh /install that fails before its transaction cleans up.

A fresh Install publishes its preparation receipt (phase preparing_layout,
no snapshot) and creates InstallRoot and StateRoot before
New-DefenseClawTransaction binds the receipt to a transaction. A refusal in
that window (for example the inspect-cowork refusal of GAP-1749) used to end
rc 1603 with both roots and the receipt left until the next /install or
/uninstall PURGE=1. The lifecycle catch now runs
Complete-DefenseClawFailedInstallPreparation, which removes them in the same
run with the same Complete-DefenseClawInstallRollbackIntent the next run would
use, or names them in rollback_leftovers with the command that clears them.
A receipt bound to a transaction, a pending transaction and an Install over
roots that already existed stay as they were.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"


def _module() -> str:
    return MODULE.read_text(encoding="utf-8")


def _function(text: str, name: str) -> str:
    start = text.index(f"function {name} {{")
    end = text.index("\nfunction ", start + 1)
    return text[start:end]


def test_the_lifecycle_catch_cleans_a_failed_fresh_install_before_reading_evidence() -> None:
    lifecycle = _function(_module(), "Invoke-DefenseClawEnterpriseLifecycle")
    # Initialised before the outer try, so the catch can read it under strict mode.
    init = lifecycle.index("    $installPreparationIntent = $null\n    $touchedVendorFolders")
    outer_try = lifecycle.index("    try {\n        # Revalidate current/global/GUID drive identity")
    assert init < outer_try
    catch = lifecycle.index("    catch {\n        if ($Action -ceq 'Install' -and $null -ne $installPreparationIntent) {")
    call = lifecycle.index("Complete-DefenseClawFailedInstallPreparation `", catch)
    evidence = lifecycle.index("Add-DefenseClawRecoveryEvidenceToError -ErrorRecord $_ -Layout $layout", catch)
    assert catch < call < evidence


def test_the_cleanup_uses_the_receipt_rollback_and_never_throws() -> None:
    helper = _function(_module(), "Complete-DefenseClawFailedInstallPreparation")
    assert "Complete-DefenseClawInstallRollbackIntent `" in helper
    assert "Add-DefenseClawRollbackLeftovers" in helper
    assert "'/install', '/uninstall PURGE=1'" in helper
    # Only a receipt that planned to create a root is cleaned.
    assert "install_root_baseline_absent" in helper and "state_root_baseline_absent" in helper
    # Every throwing call sits in a try; the function ends in catch blocks only.
    assert helper.count("    try {") == 2 and helper.count("    catch {") == 2


HARNESS = r"""
param([string]$ModulePath, [string]$Work)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Import-Module $ModulePath -PassThru -Force -DisableNameChecking
function New-Case([string]$Name) {
    $dir = Join-Path $Work $Name
    $layout = @{
        InstallRoot = (Join-Path $dir 'Program Files\Cisco\DefenseClaw')
        StateRoot = (Join-Path $dir 'ProgramData\Cisco\DefenseClaw')
        PendingPath = (Join-Path $dir 'ProgramData\Cisco\DefenseClaw\install\pending.json')
        InstallRollbackIntentPath = (Join-Path $dir 'ProgramData\Cisco\DefenseClaw-Lifecycle\install-rollback-x.json')
    }
    foreach ($p in @($layout.InstallRoot, $layout.StateRoot, (Split-Path $layout.InstallRollbackIntentPath))) {
        New-Item -ItemType Directory -Force -Path $p | Out-Null
    }
    Set-Content -LiteralPath $layout.InstallRollbackIntentPath -Value '{}'
    return $layout
}
function Invoke-Case([string]$Name, [string]$Profile, $Intent, [bool]$Pending, [string]$CompleteThrows, [bool]$GetThrows) {
    $layout = New-Case $Name
    if ($Pending) {
        New-Item -ItemType Directory -Force -Path (Split-Path $layout.PendingPath) | Out-Null
        Set-Content -LiteralPath $layout.PendingPath -Value '{}'
    }
    $out = & $module {
        param($layout, $Profile, $Intent, $CompleteThrows, $GetThrows)
        $script:DefenseClawEnterpriseProfile = $Profile
        $script:DefenseClawRollbackLeftovers = @()
        $script:completeCalls = 0
        function Get-DefenseClawInstallRollbackIntent { param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$Required)
            if ($GetThrows) { throw 'install rollback intent failed authentication' }
            return $Intent }
        function Complete-DefenseClawInstallRollbackIntent { param($Layout, $GatewayServiceName, $GuardianServiceName)
            $script:completeCalls++
            if ($CompleteThrows) { throw $CompleteThrows }
            Remove-Item -Recurse -Force -LiteralPath $Layout.InstallRoot, $Layout.StateRoot, $Layout.InstallRollbackIntentPath }
        function Write-DefenseClawLifecyclePhase { param($Stage) }
        $got = Complete-DefenseClawFailedInstallPreparation -Layout $layout -GatewayServiceName DefenseClawGateway -GuardianServiceName DefenseClawHookGuardian
        [pscustomobject]@{ got = $got; calls = $script:completeCalls; left = (@($script:DefenseClawRollbackLeftovers) -join ' | ') }
    } $layout $Profile $Intent $CompleteThrows $GetThrows
    $exists = @('InstallRoot', 'StateRoot', 'InstallRollbackIntentPath' | Where-Object { Test-Path -LiteralPath $layout[$_] }) -join ','
    "case $Name got=$($out.got) calls=$($out.calls) exists=[$exists] left=$($out.left)"
}
function Receipt([bool]$InstallAbsent, [bool]$StateAbsent, [string]$Snapshot = '', [string]$Phase = 'preparing_layout') {
    [pscustomobject]@{ phase = $Phase; snapshot_path = $Snapshot; install_root_baseline_absent = $InstallAbsent; state_root_baseline_absent = $StateAbsent }
}
Invoke-Case 'fresh' 'Standalone' (Receipt $true $true) $false '' $false
Invoke-Case 'fresh-state-only' 'Standalone' (Receipt $false $true) $false '' $false
Invoke-Case 'cleanup-refused' 'Standalone' (Receipt $true $true) $false 'refusing fresh-install root cleanup: DefenseClawGateway is registered' $false
Invoke-Case 'bound' 'Standalone' (Receipt $true $true 'C:\x\transactions\t1') $false '' $false
Invoke-Case 'pending' 'Standalone' (Receipt $true $true) $true '' $false
Invoke-Case 'committed' 'Standalone' (Receipt $true $true '' 'committed') $false '' $false
Invoke-Case 'roots-existed' 'Standalone' (Receipt $false $false) $false '' $false
Invoke-Case 'no-receipt' 'Standalone' $null $false '' $false
Invoke-Case 'unreadable' 'Standalone' $null $false '' $true
Invoke-Case 'secure-client' 'SecureClient' (Receipt $true $true) $false '' $false
"__END__"
"""

EXPECTED = {
    "fresh": ("removed", 1, ""),
    "fresh-state-only": ("removed", 1, ""),
    "cleanup-refused": ("left", 1, "InstallRoot,StateRoot,InstallRollbackIntentPath"),
    "bound": ("transaction-owned", 0, "InstallRoot,StateRoot,InstallRollbackIntentPath"),
    "pending": ("transaction-owned", 0, "InstallRoot,StateRoot,InstallRollbackIntentPath"),
    "committed": ("transaction-owned", 0, "InstallRoot,StateRoot,InstallRollbackIntentPath"),
    "roots-existed": ("roots-existed", 0, "InstallRoot,StateRoot,InstallRollbackIntentPath"),
    "no-receipt": ("no-receipt", 0, "InstallRoot,StateRoot,InstallRollbackIntentPath"),
    "unreadable": ("unreadable-receipt", 0, "InstallRoot,StateRoot,InstallRollbackIntentPath"),
    "secure-client": ("not-standalone", 0, "InstallRoot,StateRoot,InstallRollbackIntentPath"),
}


def check_harness_output(output: str) -> None:
    assert "__END__" in output, output
    lines = {line.split()[1]: line for line in output.splitlines() if line.startswith("case ")}
    for name, (got, calls, exists) in EXPECTED.items():
        line = lines.get(name, "")
        assert f"got={got} calls={calls} exists=[{exists}]" in line, (name, line, output)
        if name != "cleanup-refused":
            assert line.endswith("left="), (name, line)
    refused = lines["cleanup-refused"]
    # The leftover names the folders, the receipt, the reason and the command.
    assert "could not remove what it created (refusing fresh-install root cleanup" in refused
    assert "Program Files\\Cisco\\DefenseClaw" in refused and "install-rollback-x.json" in refused
    assert "/install" in refused and "/uninstall PURGE=1" in refused


@pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None,
                    reason="needs Windows PowerShell 7 (the module reads the Windows machine roots on import)")
def test_a_failed_fresh_install_removes_what_it_created(tmp_path: Path) -> None:
    harness = tmp_path / "harness.ps1"
    harness.write_text(HARNESS, encoding="utf-8")
    result = subprocess.run(
        [shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Work", str(tmp_path / "work")],
        capture_output=True, text=True, timeout=300, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    check_harness_output(result.stdout)
