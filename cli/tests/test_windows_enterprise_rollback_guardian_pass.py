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
- The 1.0.10 guardian puts the recorded hook (hashes.hook) back at the
  transition path only from its protected copy,
  hook-guardian\payload\defenseclaw-hook.exe, and only when that copy has the
  recorded digest. Setup never restores the copy; the failed run's guardian
  refreshes it with this release's hook on its first pass.
- early (hook_image_start_failed) and any failure before that pass: the copy is
  still the restored hook's, the guardian puts that hook back, so the file must
  stay as it is; publishing it for the guard (fix2056 16690c62f4, and
  301d88df33 when the run failed between its activating phase and that pass)
  hung the rollback.
- late (cap-f2005a) and a missing copy: the guardian leaves the guard in place,
  so the file must name the guard; keeping it (fix2012b, and 301d88df33 for a
  snapshot without its field) hung the rollback.
The readiness (Assert-DefenseClawRestoredTransactionReadyForActivation, run
here for real) reads that copy against the restored record and keeps the file
or publishes it for the guard. Once the restored hook is back it is published
for that hook. The model below is that guardian, deciding from the same copy.
A Codex writer that holds the lock at that step ends the rollback held, with no
verify after the guardian pass (the held end, 1618).
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
    'Restore-DefenseClawSnapshotHookAfterActivation', 'Get-DefenseClawEarlyHookField',
    'Assert-DefenseClawRestoredTransactionReadyForActivation', 'Get-DefenseClawRecordedHookSHA256',
    'Copy-DefenseClawHookPreimage', 'Add-DefenseClawRollbackDeferredHold', 'Get-DefenseClawHeldMessagePath')
# Present only with the fix; the cases judge behavior, not names.
$optional = @('Test-DefenseClawCodexRequirementsOwnPublication', 'Complete-DefenseClawRestoredHookGuardianPass',
    'Invoke-DefenseClawRestoredHookGuardianReconcile', 'Start-DefenseClawRestoredGuardianAgain',
    'Invoke-DefenseClawRestoredHookCodexStep', 'Test-DefenseClawRestoredGuardianKeepsGuard')
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
$script:DefenseClawRollbackDeferBusyWriter = $false
$script:DefenseClawRollbackDeferredHolds = [Collections.Generic.List[string]]::new()
$script:DefenseClawRollbackHoldsMet = 0
$script:DefenseClawRollbackCoverageDeferred = $false
# GAP-2056: the restored 1.0.10 gateway. The file names one hook; verify and
# the guardian's startup reconcile refuse it unless that is the hook at the
# transition path, and reconcile publishes it for that hook.
$script:Model1010 = $Case -like 'restored-1010*'
$script:GuardianStatus = if ($Case -ceq 'restored-1010-stopped') { 'Stopped' } else { 'Running' }
# Repair alone (keep-late): the readiness found that the guard stays.
$script:DefenseClawRollbackGuardianKeepsGuard = $Case -ceq 'keep-late'
# The guardian's protected copy at the rollback: still the restored hook's
# (early, and the P3 window: the run failed after its activating phase, before
# the forward guardian's first pass), refreshed with this release's hook by that
# pass (late), or missing.
$script:PayloadCopy = switch ($Case) {
    { $_ -in @('restored-1010-early', 'restored-1010-window') } { 'previous release hook' }
    'restored-1010-nocopy' { $null }
    default { 'transaction guard hook' }
}
# The field 301d88df33 wrote before -Phase activating; this fix reads the copy.
$script:StartedUnderGuardField = $Case -in @('restored-1010', 'restored-1010-stopped', 'restored-1010-window', 'restored-1010-busy')
# P4-1: a Codex writer holds the lock at the first check after the hook is back.
$script:BusyAfterActivation = $false
function Get-NamedHook { ([IO.File]::ReadAllText($layout.CodexMachinePolicyPath)).Trim() -replace '^managed_hook = ', '' }
function Get-LiveHook { [IO.File]::ReadAllText($layout.HookPath) }
function Assert-RestoredGuardianStarts {
    # 1.0.10 keepWindowsStandaloneHookBinaryLocked: a transition hook that is
    # not the recorded one is restored from the protected copy only when that
    # copy has the recorded digest; otherwise it stays.
    $copy = Join-Path $layout.GuardianDirectory 'payload/defenseclaw-hook.exe'
    $want = Get-DefenseClawRecordedHookSHA256 -Layout $layout
    if ((Get-Sha $layout.HookPath) -cne $want -and (Test-Path -LiteralPath $copy -PathType Leaf) -and (Get-Sha $copy) -ceq $want) {
        Copy-Item -LiteralPath $copy -Destination $layout.HookPath -Force
    }
    if ((Get-NamedHook) -cne (Get-LiveHook)) { $script:calls.Add('guardian-refused') }
}
# GAP-2128: the restored deployment metadata cannot be read (a reparse point,
# changed ACLs, bad JSON) when the readiness checks the guardian's copy.
$script:MetadataThrows = $Case -ceq 'restored-1010-badmeta'
function Get-DefenseClawDeploymentMetadata {
    param($Layout)
    if ($script:MetadataThrows) { throw 'deployment metadata is not readable' }
    [pscustomobject]@{ hashes = [pscustomobject]@{ hook = $script:RecordedHook } }
}
# The readiness around the deployment check (stubbed as in
# test_windows_enterprise_codex_writer_rollback.py); the deployment check runs
# the recovery the rollback asks for.
function Get-DefenseClawTransactionServiceStates { param($Services, $GatewayServiceName, $GuardianServiceName) @{ DefenseClawGateway = [pscustomobject]@{ existed = $true }; DefenseClawHookGuardian = [pscustomobject]@{ existed = $true }; br = [pscustomobject]@{ existed = $false }; en = [pscustomobject]@{ existed = $true } } }
function Get-DefenseClawCMIDBrokerServiceName { param($GatewayServiceName) 'br' }
function Get-DefenseClawEnumeratorServiceName { param($GuardianServiceName) 'en' }
function Test-DefenseClawTransactionBrokerTopology { param($Layout) $false }
function Test-DefenseClawServiceExists { param($Name) $false }
function Get-DefenseClawTransactionGatewayAccount { param($Snapshot) 'acct' }
function Assert-DefenseClawEnterpriseDeployment {
    param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$ServicingTransaction, [switch]$RollbackRestore,
        $TransitionHookSHA256, [switch]$AllowTransactionRecordedBrokerAbsence, [switch]$AllowTransactionRecordedEnumeratorAbsence,
        [switch]$RepairRecoveredCodexRequirements, $ExpectedGatewayAccount)
    if ($RepairRecoveredCodexRequirements) {
        Repair-DefenseClawRecoveredCodexRequirements -Layout $Layout -GatewayServiceName $GatewayServiceName
    }
}
function Test-DefenseClawStandaloneProfile { $true }
function Invoke-DefenseClawCodexRequirementsCommand {
    param($Layout, $GatewayServiceName, $Action, [string]$BaseFile = '', [switch]$Teardown)
    $script:calls.Add("codex-$Action")
    if ($script:Model1010) {
        if ($Action -ceq 'verify' -and $script:BusyAfterActivation -and $script:DefenseClawRollbackDeferBusyWriter) {
            # GAP-0999 in Invoke-DefenseClawCodexRequirementsCommand: the hold is
            # recorded and nothing is judged.
            $script:BusyAfterActivation = $false
            Add-DefenseClawRollbackDeferredHold -Message 'codex_state_unsettled: the writer is writer.exe (pid 4242) and holds the Codex writer lock'
            $script:DefenseClawRollbackCoverageDeferred = $true
            return $null
        }
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
    GuardianDirectory = (Join-Path $state 'hook-guardian')
    HookPath = (Join-Path $Scratch 'bin/defenseclaw-hook.exe')
}
$script:failure = ''
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
    $script:RecordedHook = Get-Sha $old
    [IO.File]::WriteAllText($layout.HookPath, 'transaction guard hook')
    if ($null -ne $script:PayloadCopy) {
        [void](New-Item -ItemType Directory -Force -Path (Join-Path $layout.GuardianDirectory 'payload'))
        [IO.File]::WriteAllText((Join-Path $layout.GuardianDirectory 'payload/defenseclaw-hook.exe'), $script:PayloadCopy)
    }
    $snapshot = [pscustomobject]@{
        services = @()
        early_hook_guard_copy = 'guard.bak'
        early_hook_guard_sha256 = (Get-Sha $layout.HookPath)
        early_hook_preimage_sha256 = (Get-Sha $old)
        gateway_service = 'DefenseClawGateway'
        guardian_service = 'DefenseClawHookGuardian'
        files = @([pscustomobject]@{ path = $layout.HookPath; existed = $true; backup = $old })
    }
    if ($script:StartedUnderGuardField) {
        $snapshot | Add-Member -MemberType NoteProperty -Name services_started_under_guard -Value $true
    }
    try {
        try {
            [void](Assert-DefenseClawRestoredTransactionReadyForActivation -Snapshot $snapshot -Layout $layout)
        }
        finally {
            # GAP-2128: the readiness's flags never outlive it.
            $script:calls.Add("flags-$([bool]$script:DefenseClawRollbackDeferBusyWriter)-$([bool]$script:DefenseClawRollbackTransitionHookPending)-$([bool]$script:DefenseClawRollbackGuardianKeepsGuard)")
            $script:MetadataThrows = $false
        }
        # Activation: the restored guardian's startup reconcile.
        $script:calls.Add('activation')
        Assert-RestoredGuardianStarts
        $script:BusyAfterActivation = $Case -ceq 'restored-1010-busy'
        Restore-DefenseClawSnapshotHookAfterActivation -Snapshot $snapshot -Layout $layout
    }
    catch {
        $script:failure = $_.Exception.Message
    }
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
    holds = $script:DefenseClawRollbackDeferredHolds.Count
    failure = $script:failure
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


def _assert_activates_on_the_restored_hook(result: dict) -> list:
    calls = result["calls"]
    assert result["failure"] == "", result
    assert "guardian-refused" not in calls, calls
    assert calls[-1] == "final-names-previous release hook", calls
    assert result["backups"] == 0, result
    assert result["notes"] == 0, result
    assert "event-defenseclaw_recover" not in calls, calls
    return calls


def test_a_failure_before_the_forward_guardian_pass_keeps_the_file_the_restored_guardian_needs(tmp_path: Path) -> None:
    # GAP-2056 review P3-1: the run failed after its activating phase and before
    # its guardian's first pass (301d88df33 had already written
    # services_started_under_guard). The protected copy is still the restored
    # hook's, so the restored guardian puts that hook back: the readiness must
    # keep the file, not publish it for the guard.
    calls = _assert_activates_on_the_restored_hook(_run(tmp_path, "restored-1010-window"))
    readiness = calls[: calls.index("activation")]
    assert "codex-reconcile" not in readiness, calls


def test_a_late_refusal_from_a_snapshot_without_the_field_publishes_the_file_for_the_guard(tmp_path: Path) -> None:
    # The copy was refreshed with this release's hook, so the restored guardian
    # keeps the guard; the snapshot (an older Setup's) says nothing about it.
    calls = _assert_activates_on_the_restored_hook(_run(tmp_path, "restored-1010-late-nofield"))
    readiness = calls[: calls.index("activation")]
    assert "codex-reconcile" in readiness, calls


def test_a_missing_protected_copy_publishes_the_file_for_the_guard(tmp_path: Path) -> None:
    # No copy to restore from: the restored guardian leaves the guard in place.
    calls = _assert_activates_on_the_restored_hook(_run(tmp_path, "restored-1010-nocopy"))
    readiness = calls[: calls.index("activation")]
    assert "codex-reconcile" in readiness, calls


def test_a_busy_codex_writer_after_the_hook_is_back_ends_the_rollback_held(tmp_path: Path) -> None:
    # GAP-2056 review P4-1: the check of the -RestoredHook step met a Codex
    # writer that holds the lock; it records the hold and returns. The step must
    # end held (1618, transaction pending), with no verify after the guardian
    # pass, which would fail on the file still published for the guard (1603).
    result = _run(tmp_path, "restored-1010-busy")
    calls = result["calls"]
    assert result["failure"] == "", result
    assert result["holds"] == 1, result
    wait = "guardian-wait-DefenseClawHookGuardian-True"
    after = calls[calls.index(wait):] if wait in calls else []
    assert "codex-verify" not in after, calls


def test_an_unreadable_restored_record_publishes_the_file_for_the_guard_and_resets_the_flags(tmp_path: Path) -> None:
    # GAP-2128: the readiness reads the recorded digest after it sets the
    # rollback flags and before the try whose finally resets them. A record it
    # cannot read must not throw out of that window with the flags still set; it
    # leaves the guard in place, like an unreadable copy, so the file is
    # published for the guard.
    result = _run(tmp_path, "restored-1010-badmeta")
    calls = result["calls"]
    assert "flags-False-False-False" in calls, calls
    calls = _assert_activates_on_the_restored_hook(result)
    readiness = calls[: calls.index("activation")]
    assert "codex-reconcile" in readiness, calls
