r"""GAP-2017 (P3): a failed upgrade's rollback never ends with the restored
guardian stopped by its own reconcile pass.

The GAP-2012 pass (Complete-DefenseClawRestoredHookGuardianPass) restarts the
restored guardian once the previous hook is back and waits for one fresh
reconcile. When that pass failed after it had stopped the guardian, Setup
started the guardian once more inside a catch that dropped its error, so a
second failure left the guardian stopped while the rollback reported only a
degraded event ("coverage is reported as it last published it").

Now the pass restarts only a running guardian that can be started again, a
failed pass starts it again (bounded) and checks it stays running, and a
guardian that does not come back fails the rollback (not protected).
A guardian the rollback left stopped as recorded is not started.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"

_HARNESS = r"""
param([string]$ModulePath, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not ('ServiceProcess.ServiceControllerStatus' -as [type]) -and
    -not ('System.ServiceProcess.ServiceControllerStatus' -as [type])) {
    Add-Type -TypeDefinition 'namespace ServiceProcess { public enum ServiceControllerStatus { Stopped = 1, StartPending = 2, StopPending = 3, Running = 4 } }'
}
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
# Present only with the fix; the cases judge behavior, not names.
$optional = @('Invoke-DefenseClawRestoredHookGuardianReconcile', 'Start-DefenseClawRestoredGuardianAgain')
foreach ($name in @('Complete-DefenseClawRestoredHookGuardianPass') + $optional) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) {
        if ($optional -contains $name) { continue }
        throw "missing $name"
    }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$script:RestoredGuardianStartAttempts = 3
$script:RestoredGuardianSettleMilliseconds = 0
$script:DefenseClawRollbackCodexVerifyDeferred = $false
$script:calls = [Collections.Generic.List[string]]::new()
$script:running = $Case -cne 'stopped-as-recorded'
$script:startMode = if ($Case -ceq 'disabled-running') { 4 } else { 2 }
# Start requests that fail before one succeeds (-1: every one fails).
$script:startFailures = switch ($Case) {
    'restart-fails-always' { -1 }
    'restart-fails-once' { 1 }
    default { 0 }
}
function Test-DefenseClawStandaloneProfile { $true }
function Write-DefenseClawLifecyclePhase { param($Stage) $script:calls.Add('phase') }
function Write-DefenseClawResilienceEvent { param($Marker, $Fields) $script:calls.Add("event-$Marker") }
function ConvertTo-DefenseClawBoundedDiagnostic { param($Value, $MaxLength) [string]$Value }
function Format-DefenseClawSetupAction { param($Action) "Setup $Action" }
function Get-DefenseClawServiceStartMode { param($Name) $script:startMode }
function Get-DefenseClawServiceChecked {
    param($Name)
    $status = if ($script:running) { 'Running' } else { 'Stopped' }
    [pscustomobject]@{ Name = $Name; Status = [ServiceProcess.ServiceControllerStatus]$status }
}
function Start-DefenseClawService {
    param($Name)
    $script:calls.Add("start-$Name")
    if ($script:startFailures -ne 0) {
        if ($script:startFailures -gt 0) { $script:startFailures-- }
        throw "service $Name failed during start or readiness check"
    }
    # 'starts-then-dies': SCM reports the start, the process exits at once.
    $script:running = $Case -cne 'starts-then-dies'
}
function Wait-DefenseClawFreshGuardianReconcile {
    param($Layout, $GatewayServiceName, $GuardianServiceName, $ExpectedManifestSHA256, $TimeoutSeconds, [switch]$AllowFailedTargets)
    $script:calls.Add("guardian-wait-$GuardianServiceName")
    # The real wait stops the guardian, then starts it.
    $script:running = $false
    if ($Case -ceq 'pass-ok') {
        $script:running = $true
        return 'generation-2'
    }
    Start-DefenseClawService -Name $GuardianServiceName
    throw 'guardian reconcile did not complete'
}

$snapshot = [pscustomobject]@{
    gateway_service = 'DefenseClawGateway'
    guardian_service = 'DefenseClawHookGuardian'
}
$threw = ''
try {
    Complete-DefenseClawRestoredHookGuardianPass -Snapshot $snapshot -Layout @{}
}
catch {
    $threw = [string]$_.Exception.Message
}
[ordered]@{
    calls = @($script:calls)
    running = [bool]$script:running
    threw = $threw
} | ConvertTo-Json -Compress -Depth 4
"""


def _run(tmp_path: Path, case: str) -> dict:
    engine = shutil.which("pwsh")
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "rollback-guardian-restart.ps1"
    harness.write_text(_HARNESS, encoding="utf-8")
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Case", case],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_a_guardian_that_does_not_start_again_fails_the_rollback(tmp_path: Path) -> None:
    result = _run(tmp_path, "restart-fails-always")
    assert result["running"] is False, result
    assert "did not start again" in result["threw"], result
    assert "not protected" in result["threw"], result
    # The wait's own start, then three bounded attempts; no degraded-only end.
    assert result["calls"].count("start-DefenseClawHookGuardian") == 4, result
    assert "event-defenseclaw_degraded" not in result["calls"], result


def test_a_failed_pass_starts_the_guardian_again_until_it_runs(tmp_path: Path) -> None:
    result = _run(tmp_path, "restart-fails-once")
    assert result["threw"] == "", result
    assert result["running"] is True, result
    assert "event-defenseclaw_degraded" in result["calls"], result


def test_a_guardian_that_starts_and_exits_fails_the_rollback(tmp_path: Path) -> None:
    result = _run(tmp_path, "starts-then-dies")
    assert result["running"] is False, result
    assert "did not start again" in result["threw"], result
    assert "started and then stopped" in result["threw"], result


def test_a_guardian_stopped_as_recorded_is_not_started(tmp_path: Path) -> None:
    result = _run(tmp_path, "stopped-as-recorded")
    assert result["threw"] == "", result
    assert result["running"] is False, result
    assert not any(call.startswith(("guardian-wait-", "start-")) for call in result["calls"]), result


def test_a_running_guardian_with_a_disabled_start_mode_is_not_stopped(tmp_path: Path) -> None:
    result = _run(tmp_path, "disabled-running")
    assert result["threw"] == "", result
    assert result["running"] is True, result
    assert not any(call.startswith(("guardian-wait-", "start-")) for call in result["calls"]), result
    assert "event-defenseclaw_degraded" in result["calls"], result


def test_a_pass_that_finishes_leaves_the_guardian_running_without_events(tmp_path: Path) -> None:
    result = _run(tmp_path, "pass-ok")
    assert result["threw"] == "", result
    assert result["running"] is True, result
    assert result["calls"].count("guardian-wait-DefenseClawHookGuardian") == 1, result
    assert "start-DefenseClawHookGuardian" not in result["calls"], result
    assert not any(call.startswith("event-") for call in result["calls"]), result
