r"""GAP-0999 (r109): a Codex writer that keeps its transaction open must never
leave the Setup services stopped.

IB27 EW27-03: a SYSTEM program kept the Codex writer lock odd for a whole
Setup /ensure. The strict callers refused with codex_state_unsettled (1603),
then the rollback could not finish (the guardian could not publish the
coverage its proof waits for while the writer stays stuck), the transaction was
left pending and DefenseClawGateway and DefenseClawHookEnumerator stayed
stopped. The rollback now defers the state check and the guardian proof the way
a held file defers them (GAP-0947): the restored services run, the writer is
named, /repair is the way out, the transaction is pending and the exit code is
1618 (a refusal whose rollback was clean stays 1603). Standalone only: Secure
Client has no writer lock and keeps its rollback as it was.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
GO = ROOT / "internal" / "cli" / "windows_enterprise_standalone.go"


def _text() -> str:
    return MODULE.read_text(encoding="utf-8")


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


def test_the_refusal_of_the_forward_run_names_the_writer() -> None:
    wait = _function_body(_text(), "Wait-DefenseClawCodexManagedHooksStateSettled")
    assert "Get-DefenseClawCodexWriterHolderText -Path $Path" in wait
    # Best effort: the wording never decides whether the run is refused.
    assert "catch { $writerText = '' }" in wait
    holder = _function_body(_text(), "Get-DefenseClawCodexWriterHolderText")
    assert ".defenseclaw-managed-hooks.writer.lock" in holder
    assert "GetFileHolders" in holder and "Format-DefenseClawProcessInUse" in holder
    assert "FORCE" not in holder


def test_the_rollback_state_check_defers_a_stuck_writer_on_the_standalone_profile_only() -> None:
    body = _function_body(_text(), "Assert-DefenseClawEnterpriseDeployment")
    start = body.index("Assert-DefenseClawCodexManagedHooksStateFile -Layout $Layout")
    window = body[start : start + 3200]
    assert "$rollbackStateCheck = [bool]($RepairRecoveredCodexRequirements -and $ServicingTransaction -and" in window
    assert "(Test-DefenseClawStandaloneProfile))" in window
    assert "if ($rollbackStateCheck -and" in window
    assert "StartsWith('codex_state_unsettled: '" in window
    assert "New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $Layout" in window
    # A forward run keeps the throw: the deferral needs the rollback flags.
    assert window.index("$rollbackStateCheck = ") < window.index("else {")


def test_the_guardian_proof_is_deferred_for_a_stuck_writer_only_after_it_failed() -> None:
    body = _function_body(_text(), "Start-DefenseClawTransactionServices")
    proof = body.index("Wait-DefenseClawFreshGuardianReconcile")
    deferral = body.index("Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $Layout")
    assert proof < body.index("catch {", proof) < deferral
    # Any other proof failure still fails the recovery.
    assert "else {\n                        throw" in body[deferral : deferral + 1800]
    helper = _function_body(_text(), "Test-DefenseClawGuardianProofDeferredByCodexWriter")
    assert helper.index("Test-DefenseClawStandaloneProfile") < helper.index("Add-DefenseClawRollbackDeferredHold")
    assert "% 2) -eq 0" in helper and "return $false" in helper


def test_a_refusal_whose_rollback_met_the_writer_again_is_named_once() -> None:
    body = _function_body(_text(), "Invoke-DefenseClawInstallLikeLifecycle")
    assert "$firstFailure.StartsWith('codex_state_unsettled: '" in body
    assert "$rollbackHeld.StartsWith('codex_state_unsettled: '" in body


def test_the_recoveries_that_start_the_services_keep_the_writer_deferral() -> None:
    text = _text()
    assert text.count("Clear-DefenseClawRollbackDeferredHolds -KeepCodexWriter") == 2
    # The rest clear everything, as before.
    assert text.count("Clear-DefenseClawRollbackDeferredHolds\n") >= 2


def test_the_exit_code_is_the_held_rollback_convention_when_the_rollback_is_pending() -> None:
    go = GO.read_text(encoding="utf-8")
    start = go.index('case "codex_state_unsettled":')
    window = go[start : start + 700]
    assert "if result.TransactionPending {" in window
    assert "return enterprisestatus.WindowsExitBusy" in window
    assert (
        '(report.TransactionPending && windowsBundleHasCode(result.Errors[firstError:], "codex_state_unsettled"))'
        in go
    )


_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case, [int]$Standalone = 1)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Test-DefenseClawCodexWriterLockBusyMessage', 'New-DefenseClawCodexWriterBusyRefusal', 'Get-DefenseClawOptionalLayoutValue', 'Get-DefenseClawCodexManagedHooksWriterCounter', 'Test-DefenseClawRollbackHeldMessage', 'New-DefenseClawCodexWriterUnsettledHeldMessage', 'Test-DefenseClawGuardianProofDeferredByCodexWriter', 'Clear-DefenseClawRollbackDeferredHolds', 'Test-DefenseClawRollbackCoverageDeferred', 'Get-DefenseClawHeldMessagePath', 'Add-DefenseClawRollbackDeferredHold', 'Assert-DefenseClawRollbackHoldsResolved')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing $name" }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$script:DefenseClawRollbackDeferredHolds = [Collections.Generic.List[string]]::new()
$script:DefenseClawRollbackCoverageDeferred = $false
$script:events = [Collections.Generic.List[string]]::new()
function Test-DefenseClawStandaloneProfile { [bool]$Standalone }
function Write-DefenseClawResilienceEvent { param([string]$Marker, [hashtable]$Fields) $script:events.Add($Marker + ': ' + $Fields['reason']) }
function Format-DefenseClawSetupAction { param([string]$Action) "Setup $Action" }
function Get-DefenseClawCodexWriterHolderText { param([string]$Path) 'the writer is writer.exe (pid 4242, account NT AUTHORITY\SYSTEM)' }
$state = Join-Path $Scratch '.defenseclaw-managed-hooks.state'
$lock = Join-Path $Scratch '.defenseclaw-managed-hooks.writer.lock'
function Set-Counter([int]$Size) { [IO.File]::WriteAllBytes($lock, [byte[]]::new($Size)) }
$layout = @{ CodexManagedHooksStatePath = $state }
$out = [ordered]@{}
switch ($Case) {
    'odd' {
        Set-Counter 19
        $out.deferred = [bool](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
        $out.holds = @($script:DefenseClawRollbackDeferredHolds)
        $out.coverage = [bool](Test-DefenseClawRollbackCoverageDeferred)
        $out.held = [bool](@($out.holds).Count -gt 0 -and (Test-DefenseClawRollbackHeldMessage -Message $out.holds[0]))
        # The counter moves between two steps of the same rollback: one entry.
        Set-Counter 21
        [void](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
        $out.holdsAfterSecond = @($script:DefenseClawRollbackDeferredHolds).Count
        $ended = ''
        try { Assert-DefenseClawRollbackHoldsResolved } catch { $ended = $_.Exception.Message }
        $out.ended = $ended
        $out.after = @($script:DefenseClawRollbackDeferredHolds).Count
        $out.coverageAfter = [bool]$script:DefenseClawRollbackCoverageDeferred
    }
    'even' {
        Set-Counter 18
        $out.deferred = [bool](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
        $out.holds = @($script:DefenseClawRollbackDeferredHolds)
        $out.coverage = [bool]$script:DefenseClawRollbackCoverageDeferred
    }
    'no-lock' {
        $out.deferred = [bool](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
        $out.holds = @($script:DefenseClawRollbackDeferredHolds)
    }
    'busy' {
        $busy = @(
            'Codex requirements reconcile failed: timed out waiting 10s for Codex machine policy lock',
            'Codex requirements verify failed: open Codex machine policy lock: The process cannot access the file because it is being used by another process.',
            'open Codex machine policy lock: sharing violation'
        )
        $notBusy = @(
            'Codex requirements reconcile failed: allow_managed_hooks_only=false conflicts with required isolation',
            'Codex requirements verify failed: hooks.SessionStart has no DefenseClaw managed group',
            'acquire Codex machine policy lock: Access is denied.',
            ''
        )
        $out.busy = @($busy | ForEach-Object { [bool](Test-DefenseClawCodexWriterLockBusyMessage -Message $_) })
        $out.notBusy = @($notBusy | ForEach-Object { [bool](Test-DefenseClawCodexWriterLockBusyMessage -Message $_) })
        $out.refusal = New-DefenseClawCodexWriterBusyRefusal -Layout $layout -Action 'reconcile' -Detail $busy[0]
        $out.refusalIsRollbackHeld = [bool](Test-DefenseClawRollbackHeldMessage -Message $out.refusal)
    }
    'forward-refusal' {
        $refusal = 'codex_state_unsettled: the Codex writer transaction counter next to X stayed at 3 (odd: a transaction is open) for 30 seconds (the writer is writer.exe (pid 4242)), so the Codex managed-hooks state could not be judged and this run stopped (an install, repair, ensure or upgrade that had started is rolled back, an upgrade to the release it came from; a verify changes nothing). Next step: run Setup /repair again once no Codex writer is running'
        $out.held = [bool](Test-DefenseClawRollbackHeldMessage -Message $refusal)
    }
    'keep' {
        Set-Counter 19
        [void](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
        Add-DefenseClawRollbackDeferredHold -Message 'hook_in_use: x has C:\h.exe, the installed hook, open'
        Clear-DefenseClawRollbackDeferredHolds -KeepCodexWriter
        $out.kept = @($script:DefenseClawRollbackDeferredHolds | ForEach-Object { $_.Substring(0, 22) })
        $out.coverageKept = [bool]$script:DefenseClawRollbackCoverageDeferred
        Clear-DefenseClawRollbackDeferredHolds
        $out.cleared = @($script:DefenseClawRollbackDeferredHolds).Count
        $out.coverageCleared = [bool]$script:DefenseClawRollbackCoverageDeferred
    }
}
$out.events = @($script:events)
$out | ConvertTo-Json -Compress -Depth 4
"""


def _run(tmp_path: Path, case: str, standalone: bool = True) -> dict:
    engine = shutil.which("pwsh")
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "codex-writer-rollback.ps1"
    harness.write_text(_HARNESS, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Scratch", str(scratch), "-Case", case,
         "-Standalone", "1" if standalone else "0"],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_a_stuck_writer_defers_the_proof_and_ends_the_rollback_retryable(tmp_path: Path) -> None:
    result = _run(tmp_path, "odd")
    assert result["deferred"] is True, result
    (hold,) = result["holds"]
    # The code first, the writer by name, /repair (never the forced uninstall),
    # the pending transaction, and what was left as it was.
    assert hold.startswith("codex_state_unsettled: "), result
    assert "the writer is writer.exe (pid 4242, account NT AUTHORITY\\SYSTEM)" in hold, result
    assert "stayed at 19 (odd: a transaction is open" in hold, result
    assert "run Setup /repair" in hold and "the transaction is still pending" in hold, result
    assert "FORCE" not in hold and "uninstall" not in hold.lower(), result
    assert "an MDM retries exit 1618 on its own" in hold, result
    assert result["held"] is True and result["coverage"] is True, result
    # One entry for the writer, whatever the counter did in between.
    assert result["holdsAfterSecond"] == 1, result
    assert result["ended"].startswith("codex_state_unsettled: "), result
    assert "The guardian's coverage was not proven by this rollback" in result["ended"], result
    assert "cannot publish coverage while a Codex writer keeps its transaction open" in result["ended"], result
    assert result["after"] == 0 and result["coverageAfter"] is False, result


def test_a_settled_writer_defers_nothing(tmp_path: Path) -> None:
    for case in ("even", "no-lock"):
        (tmp_path / case).mkdir()
        result = _run(tmp_path / case, case)
        assert result["deferred"] is False, result
        assert result["holds"] == [], result
        assert result.get("coverage", False) is False, result


def test_secure_client_has_no_writer_lock_and_defers_nothing(tmp_path: Path) -> None:
    result = _run(tmp_path, "odd", standalone=False)
    assert result["deferred"] is False, result
    assert result["holds"] == [], result
    assert result["coverage"] is False, result


def test_the_refusal_of_a_forward_run_is_not_a_rollback_deferral(tmp_path: Path) -> None:
    # Only the rollback's own words make the message a deferral: a stray throw of
    # the wait inside a rollback is not read as one.
    assert _run(tmp_path, "forward-refusal")["held"] is False


def test_the_services_recovery_keeps_only_the_writer_deferral(tmp_path: Path) -> None:
    result = _run(tmp_path, "keep")
    assert result["kept"] == ["codex_state_unsettled:"], result
    assert result["coverageKept"] is True, result
    assert result["cleared"] == 0 and result["coverageCleared"] is False, result


def test_a_busy_writer_lock_is_told_apart_from_a_defect_of_the_policy_file(tmp_path: Path) -> None:
    # GAP-0999: the gateway's lock-busy answers (the sharing violation of an
    # exclusive writer, the byte-range lock that is never given) are not the
    # hand edit the Codex policy recovery (GAP-0802, GAP-0955) acts on.
    result = _run(tmp_path, "busy")
    assert result["busy"] == [True, True, True], result
    assert result["notBusy"] == [False, False, False, False], result
    refusal = result["refusal"]
    assert refusal.startswith("codex_state_unsettled: a Codex writer holds the writer lock next to "), result
    assert "the writer is writer.exe (pid 4242, account NT AUTHORITY\\SYSTEM)" in refusal, result
    assert "run Setup /repair again once no Codex writer is running" in refusal, result
    assert "timed out waiting 10s for Codex machine policy lock" in refusal, result
    assert "FORCE" not in refusal and result["refusalIsRollbackHeld"] is False, result


def test_a_busy_writer_never_reaches_the_recovery_that_rebuilds_the_policy_file() -> None:
    text = _text()
    command = _function_body(text, "Invoke-DefenseClawCodexRequirementsCommand")
    assert command.index("Test-DefenseClawStandaloneProfile") < command.index("New-DefenseClawCodexWriterBusyRefusal")
    assert command.index("New-DefenseClawCodexWriterBusyRefusal") < command.index('throw "Codex requirements $Action failed: $detail"')
    forward = _function_body(text, "Invoke-DefenseClawCodexRequirementsReconcileOrRecover")
    assert forward.index("codex_state_unsettled: ") < forward.index("Repair-DefenseClawRecoveredCodexRequirements")
    repair = _function_body(text, "Repair-DefenseClawRecoveredCodexRequirements")
    # The file is judged and touched only after the busy answers are told apart.
    assert repair.index("$verifyError.StartsWith('codex_state_unsettled: '") < repair.index("$backupPath = ''")
    assert repair.index("$mergeError.StartsWith('codex_state_unsettled: '") < repair.index("Get-DefenseClawRecordedCodexRequirementsPreimage")
    assert "throw $verifyError" in repair and "throw $mergeError" in repair
    # The rollback turns the recovery's busy answer into its own deferral.
    deployment = _function_body(text, "Assert-DefenseClawEnterpriseDeployment")
    assert "$recoveryMessage = New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $Layout" in deployment
    deployment = _function_body(text, "Assert-DefenseClawEnterpriseDeployment")
    verify = deployment.index("-Action $(if ($codexTargetEnabled) { 'verify' } else { 'inspect' }))")
    assert "New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $Layout" in deployment[verify : verify + 1200]
