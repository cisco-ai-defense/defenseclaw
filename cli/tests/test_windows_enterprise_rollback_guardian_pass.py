r"""GAP-2012 (P2): a failed upgrade's rollback reports coverage the restored
guardian has settled, and keeps the requirements.toml DefenseClaw published.

A standalone upgrade puts its own hook at the transition path before it stops
the services (the GAP-0993 guard) and the rollback puts the previous hook back
only after activation. Until then every writer resolves no launch folder for
that hook:

- The readiness check of the restored requirements.toml named the guard's
  folder as the managed directory. DefenseClaw's own file was judged a hand
  edit and the GAP-0802 recovery replaced it, saved as
  requirements.toml.hand-edited.*.bak.
- The restored guardian's first reconcile published the machine policy for
  the guard. The result then reported 54 machine_policy_not_covered and
  cov=False until the guardian's next pass.

The readiness now takes a file that is exactly DefenseClaw's last
publication for no hand edit (no backup, no recovery note). Once the hook is
back, the guardian is restarted and Setup waits, bounded, for one fresh
reconcile before the result. A real hand edit still goes through the recovery.

GAP-2056: the restored 1.0.10 guardian refuses its startup reconcile while
the file names another hook's folder than the one it resolves ("hooks.
windows_managed_dir ... does not match protected managed directory"), so the
rollback never activated. Which hook it resolves depends on how far the failed
run got:
- late (cap-f2005a: this release's services had started under the guard, so
  the restored guardian finds this release's records and keeps the guard): the
  file must name the guard; keeping it (fix2012b) hung the rollback;
- early (hook_image_start_failed, nothing started): the restored guardian puts
  its own hook back on its first start, so the file must stay as it is;
  publishing it for the guard (fix2056 16690c62f4) hung the rollback.
The readiness reads services_started_under_guard, which the forward run
records, and keeps the file or publishes it for the guard. Once the restored
hook is back it is published for that hook. The model below is that guardian.
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
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
$real = @('Repair-DefenseClawRecoveredCodexRequirements', 'Read-DefenseClawSmallJson',
    'Get-DefenseClawPlainFileSha256', 'Get-DefenseClawOptionalLayoutValue',
    'Restore-DefenseClawSnapshotHookAfterActivation', 'Get-DefenseClawEarlyHookField')
# Present only with the fix; the cases judge behavior, not names.
$optional = @('Test-DefenseClawCodexRequirementsOwnPublication', 'Complete-DefenseClawRestoredHookGuardianPass',
    'Invoke-DefenseClawRestoredHookGuardianReconcile', 'Start-DefenseClawRestoredGuardianAgain',
    'Invoke-DefenseClawRestoredHookCodexStep')
foreach ($name in @($real + $optional)) {
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
$script:calls = [Collections.Generic.List[string]]::new()
$script:VerifyFails = $true
$script:DefenseClawRecoveredCodexRequirementsNotes = @()
$script:DefenseClawRollbackTransitionHookPending = $false
$script:DefenseClawRollbackCodexVerifyDeferred = $false
# GAP-2056: the restored 1.0.10 gateway. The file names one hook; verify and
# the guardian's startup reconcile refuse it unless that is the hook at the
# transition path, and reconcile publishes it for that hook.
$script:Model1010 = $Case -like 'restored-1010*'
$script:GuardianStatus = if ($Case -ceq 'restored-1010-stopped') { 'Stopped' } else { 'Running' }
# Late: the failed run had started its services under the guard.
$script:DefenseClawRollbackGuardianKeepsGuard = $Case -in @('restored-1010', 'restored-1010-stopped', 'keep-late')
$script:EarlyRefusal = $Case -ceq 'restored-1010-early'
function Get-NamedHook { ([IO.File]::ReadAllText($layout.CodexMachinePolicyPath)).Trim() -replace '^managed_hook = ', '' }
function Get-LiveHook { [IO.File]::ReadAllText($layout.HookPath) }
function Assert-RestoredGuardianStarts {
    if ($script:EarlyRefusal) {
        # No record of the failed release: the guardian puts its own hook back.
        [IO.File]::WriteAllText($layout.HookPath, 'previous release hook')
    }
    if ((Get-NamedHook) -cne (Get-LiveHook)) { $script:calls.Add('guardian-refused') }
}
function Test-DefenseClawStandaloneProfile { $true }
function Invoke-DefenseClawCodexRequirementsCommand {
    param($Layout, $GatewayServiceName, $Action, [string]$BaseFile = '', [switch]$Teardown)
    $script:calls.Add("codex-$Action")
    if ($script:Model1010) {
        if ($Action -ceq 'verify' -and (Get-NamedHook) -cne (Get-LiveHook)) {
            throw "Codex requirements verify failed: hooks.windows_managed_dir names $(Get-NamedHook), not $(Get-LiveHook)"
        }
        if ($Action -ceq 'reconcile') {
            [IO.File]::WriteAllText($Layout.CodexMachinePolicyPath, "managed_hook = $(Get-LiveHook)`n")
            $record = Get-Content -Raw -LiteralPath $Layout.CodexRequirementsOwnershipPath | ConvertFrom-Json
            $record.postimage_sha256 = Get-Sha $Layout.CodexMachinePolicyPath
            [IO.File]::WriteAllText($Layout.CodexRequirementsOwnershipPath, ($record | ConvertTo-Json))
        }
        return [pscustomobject]@{ ok = $true }
    }
    if ($Action -ceq 'verify' -and $script:VerifyFails) {
        throw 'Codex requirements verify failed: hooks.windows_managed_dir="C:\\Program Files\\Cisco\\DefenseClaw\\bin" does not match protected managed directory "C:\\Program Files\\Cisco\\DefenseClaw\\bin\\hooks\\6081ba06f39a5eb8"'
    }
    if ($Action -ceq 'reconcile') { $script:VerifyFails = $false }
    [pscustomobject]@{ ok = $true }
}
function Get-DefenseClawBlockedCodexStatePath { param($Layout) '' }
function Assert-DefenseClawNoReparsePath { param($Path, [switch]$AllowMissingLeaf) }
function Test-DefenseClawFileReadBlocked { param($Path) $false }
function Test-DefenseClawFileDeleteBlocked { param($Path) $false }
function New-DefenseClawProtectedDirectory { param($Path) [void](New-Item -ItemType Directory -Force -Path $Path) }
function Write-DefenseClawLifecyclePhase { param($Stage) $script:calls.Add("phase") }
function Write-DefenseClawResilienceEvent { param($Marker, $Fields) $script:calls.Add("event-$Marker") }
function ConvertTo-DefenseClawBoundedDiagnostic { param($Value, $MaxLength) [string]$Value }
function Test-DefenseClawManagedHooksCommittedTeardownSupported { param($Layout, $GatewayServiceName, $Capability) $true }
function Get-DefenseClawRecordedCodexRequirementsPreimage { param($Layout) , ([byte[]]@()) }
function Format-DefenseClawSetupAction { param($Action) "Setup $Action" }
function Assert-DefenseClawDescendant { param($Path, $Root, $Label) $Path }
function Install-DefenseClawFileAtomic {
    param($Source, $Destination, $ExpectedSHA256, [switch]$SkipIfContentMatches)
    $script:calls.Add('hook-install')
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}
function Wait-DefenseClawFreshGuardianReconcile {
    param($Layout, $GatewayServiceName, $GuardianServiceName, $ExpectedManifestSHA256, $TimeoutSeconds, [switch]$AllowFailedTargets)
    $script:calls.Add("guardian-wait-$GuardianServiceName-$([bool]$AllowFailedTargets)")
    if ($script:Model1010) { Assert-RestoredGuardianStarts }
}
function Start-DefenseClawService { param($Name) $script:calls.Add("start-$Name") }
# GAP-2017: the pass restarts only a running guardian that can start again.
function Get-DefenseClawServiceChecked { param($Name) [pscustomobject]@{ Name = $Name; Status = $script:GuardianStatus } }
function Get-DefenseClawServiceStartMode { param($Name) 2 }
function Test-DefenseClawRollbackHeldMessage { param($Message) $false }
function Add-DefenseClawRollbackDeferredHold { param($Message) $script:calls.Add('held') }

function Get-Sha([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$state = Join-Path $Scratch 'state'
$install = Join-Path $state 'install'
$codex = Join-Path $Scratch 'codex'
[void](New-Item -ItemType Directory -Force -Path $install, $codex, (Join-Path $Scratch 'bin'))
$requirements = Join-Path $codex 'requirements.toml'
$ownership = Join-Path $install 'codex-requirements-ownership.json'
$layout = @{
    CodexMachinePolicyPath = $requirements
    CodexRequirementsOwnershipPath = $ownership
    InstallStateDirectory = $install
    StateRoot = $state
    HookPath = (Join-Path $Scratch 'bin/defenseclaw-hook.exe')
}
if ($script:Model1010) {
    # The 1.0.10 install published the file for its own hook before the upgrade.
    [IO.File]::WriteAllText($requirements, "managed_hook = previous release hook`n")
}
else {
    [IO.File]::WriteAllText($requirements, "[[hooks.SessionStart]]`n# defenseclaw-hook published`n")
}
$published = Get-Sha $requirements
if ($Case -ceq 'handedit') {
    # An administrator changed the file after DefenseClaw published it.
    [IO.File]::AppendAllText($requirements, "allow_managed_hooks_only = false`n")
}
[IO.File]::WriteAllText($ownership, (@{
    schema_version = 2
    requirements_path = $requirements
    preimage_existed = $false
    postimage_sha256 = $published
} | ConvertTo-Json))
$before = Get-Sha $requirements

if ($Case -in @('keep', 'keep-late', 'handedit')) {
    $script:DefenseClawRollbackTransitionHookPending = $true
    Repair-DefenseClawRecoveredCodexRequirements -Layout $layout -GatewayServiceName 'DefenseClawGateway'
}
elseif ($script:Model1010) {
    # The rollback restored the 1.0.10 payload and requirements.toml; the
    # transaction's guard is still the hook until after activation.
    $old = Join-Path $state 'hook.bak'
    [IO.File]::WriteAllText($old, 'previous release hook')
    [IO.File]::WriteAllText($layout.HookPath, 'transaction guard hook')
    $snapshot = [pscustomobject]@{
        early_hook_guard_copy = 'guard.bak'
        early_hook_preimage_sha256 = (Get-Sha $old)
        gateway_service = 'DefenseClawGateway'
        guardian_service = 'DefenseClawHookGuardian'
        files = @([pscustomobject]@{ path = $layout.HookPath; existed = $true; backup = $old })
    }
    $script:DefenseClawRollbackTransitionHookPending = $true
    Repair-DefenseClawRecoveredCodexRequirements -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    $script:DefenseClawRollbackTransitionHookPending = $false
    # Activation: the restored guardian's startup reconcile.
    $script:calls.Add('activation')
    Assert-RestoredGuardianStarts
    Restore-DefenseClawSnapshotHookAfterActivation -Snapshot $snapshot -Layout $layout
    $script:calls.Add("final-names-$(Get-NamedHook)")
}
elseif ($Case -in @('restore', 'restore-same')) {
    $old = Join-Path $state 'hook.bak'
    [IO.File]::WriteAllText($old, 'previous release hook')
    $oldDigest = Get-Sha $old
    $current = if ($Case -ceq 'restore') { 'transaction guard hook' } else { 'previous release hook' }
    [IO.File]::WriteAllText($layout.HookPath, $current)
    $snapshot = [pscustomobject]@{
        early_hook_guard_copy = 'guard.bak'
        early_hook_preimage_sha256 = $oldDigest
        gateway_service = 'DefenseClawGateway'
        guardian_service = 'DefenseClawHookGuardian'
        files = @([pscustomobject]@{ path = $layout.HookPath; existed = $true; backup = $old })
    }
    # The readiness deferred the Codex check of DefenseClaw's own file.
    $script:DefenseClawRollbackCodexVerifyDeferred = ($Case -ceq 'restore')
    $script:VerifyFails = $false
    Restore-DefenseClawSnapshotHookAfterActivation -Snapshot $snapshot -Layout $layout
}
$backups = @(Get-ChildItem -LiteralPath $install -Recurse -Filter 'requirements.toml.hand-edited.*' -ErrorAction SilentlyContinue)
[ordered]@{
    calls = @($script:calls)
    unchanged = ((Get-Sha $requirements) -ceq $before)
    backups = $backups.Count
    deferred = [bool]$script:DefenseClawRollbackCodexVerifyDeferred
    notes = @($script:DefenseClawRecoveredCodexRequirementsNotes).Count
} | ConvertTo-Json -Compress -Depth 4
"""


def _run(tmp_path: Path, case: str) -> dict:
    engine = shutil.which("pwsh")
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "rollback-guardian-pass.ps1"
    harness.write_text(_HARNESS, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Scratch", str(scratch), "-Case", case],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_the_rollback_keeps_the_requirements_defenseclaw_published_while_the_guard_is_the_hook(tmp_path: Path) -> None:
    result = _run(tmp_path, "keep")
    assert result["backups"] == 0, result
    assert result["unchanged"] is True, result
    assert "codex-reconcile" not in result["calls"], result
    assert result["notes"] == 0, result
    assert result["deferred"] is True, result


def test_after_services_started_under_the_guard_the_own_file_is_published_for_it(tmp_path: Path) -> None:
    result = _run(tmp_path, "keep-late")
    assert result["backups"] == 0, result
    assert result["notes"] == 0, result
    assert "event-defenseclaw_recover" not in result["calls"], result
    assert "codex-reconcile" in result["calls"], result
    assert result["deferred"] is True, result


def test_a_hand_edit_is_still_recovered_while_the_guard_is_the_hook(tmp_path: Path) -> None:
    result = _run(tmp_path, "handedit")
    assert result["backups"] == 1, result
    assert "codex-reconcile" in result["calls"], result
    assert result["notes"] == 1, result
    assert result["deferred"] is False, result


def test_the_restored_hook_gets_a_fresh_guardian_pass_before_the_result(tmp_path: Path) -> None:
    calls = _run(tmp_path, "restore")["calls"]
    wait = "guardian-wait-DefenseClawHookGuardian-True"
    assert calls.count(wait) == 1, calls
    assert calls.index("hook-install") < calls.index(wait), calls
    # The Codex check the readiness deferred runs after that pass.
    assert "codex-verify" in calls[calls.index(wait):], calls


def test_no_extra_guardian_pass_when_the_previous_hook_was_already_in_place(tmp_path: Path) -> None:
    calls = _run(tmp_path, "restore-same")["calls"]
    assert not any(call.startswith("guardian-wait-") for call in calls), calls
    assert "codex-verify" not in calls, calls


def test_the_rollback_over_published_1_0_10_activates_and_ends_on_the_restored_hook(tmp_path: Path) -> None:
    # GAP-2056 late refusal (cap-f2005a): the restored 1.0.10 guardian keeps
    # the guard and refused its startup reconcile on the kept file.
    result = _run(tmp_path, "restored-1010")
    calls = result["calls"]
    assert "guardian-refused" not in calls, calls
    wait = "guardian-wait-DefenseClawHookGuardian-True"
    assert calls.count(wait) == 1, calls
    # The file names the restored hook before the guardian restarts for it.
    assert calls.index("hook-install") < max(i for i, c in enumerate(calls) if c == "codex-reconcile") < calls.index(wait), calls
    assert "codex-verify" in calls[calls.index(wait):], calls
    assert calls[-1] == "final-names-previous release hook", calls
    assert result["backups"] == 0, result
    assert result["notes"] == 0, result
    assert "event-defenseclaw_recover" not in calls, calls
    assert result["deferred"] is False, result


def test_the_rollback_over_published_1_0_10_ends_on_the_restored_hook_with_the_guardian_stopped(tmp_path: Path) -> None:
    # GAP-2017: a guardian the rollback left stopped gets no pass; the file
    # still goes back to the restored hook.
    result = _run(tmp_path, "restored-1010-stopped")
    calls = result["calls"]
    assert not any(call.startswith("guardian-wait-") for call in calls), calls
    assert calls[-1] == "final-names-previous release hook", calls
    assert result["backups"] == 0, result
    assert result["notes"] == 0, result


def test_an_early_refusal_rollback_over_published_1_0_10_activates_on_the_restored_hook(tmp_path: Path) -> None:
    # GAP-2056 early refusal (hook_image_start_failed, replay TST-14605): the
    # restored 1.0.10 guardian puts its hook back and refused a file published
    # for the guard.
    result = _run(tmp_path, "restored-1010-early")
    calls = result["calls"]
    assert "guardian-refused" not in calls, calls
    assert "codex-reconcile" not in calls, calls
    assert calls[-1] == "final-names-previous release hook", calls
    assert result["backups"] == 0, result
    assert result["notes"] == 0, result
    assert "event-defenseclaw_recover" not in calls, calls
