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
    text = _text()
    # The state check itself defers, under the flag only a standalone rollback sets; the
    # lines of Assert-DefenseClawEnterpriseDeployment around it stay rel's.
    check = _function_body(text, "Assert-DefenseClawCodexManagedHooksStateFile")
    gate = check.index("if ($script:DefenseClawRollbackDeferBusyWriter) {")
    wait = check.index("$settled = Wait-DefenseClawCodexManagedHooksStateSettled")
    assert check.index("Assert-DefenseClawCodexManagedHooksStateFilePreflight") < gate < wait
    window = check[gate:wait]
    assert "StartsWith('codex_state_unsettled: '" in window
    assert "New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $Layout" in window
    assert "return\n" in window and "throw\n" in window
    body = _function_body(text, "Assert-DefenseClawEnterpriseDeployment")
    assert "GAP-0999" not in body


def test_the_guardian_proof_defers_for_any_holder_of_the_writer_lock_standalone_only() -> None:
    text = _text()
    # Start-DefenseClawTransactionServices keeps its text: the deferral is made by the
    # two helpers it already calls, before the proof and after a failed one.
    services = _function_body(text, "Start-DefenseClawTransactionServices")
    assert "Test-DefenseClawGuardianProofDeferredByCodexWriter" not in services
    assert "Set-DefenseClawRollbackGuardianStateDeferral -Layout $Layout" in services
    assert "if (-not (Resolve-DefenseClawRollbackLateGuardianHold `\n" in services
    before = _function_body(text, "Set-DefenseClawRollbackGuardianStateDeferral")
    assert before.index("Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $Layout") < before.index("Get-DefenseClawGuardianStateHold")
    late = _function_body(text, "Resolve-DefenseClawRollbackLateGuardianHold")
    gate = late.index("Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $Layout")
    assert late.index("(Test-DefenseClawStandaloneProfile) -and") < gate < late.index("if (-not (Test-DefenseClawStandaloneProfile) -or")
    assert "-notmatch '^guardian_state_held: '" in late[:gate]
    helper = _function_body(text, "Test-DefenseClawGuardianProofDeferredByCodexWriter")
    assert helper.index("Test-DefenseClawStandaloneProfile") < helper.index("Add-DefenseClawRollbackDeferredHold")
    # Any named holder defers, whatever the counter parity (an odd counter alone defers too).
    assert "% 2) -ne 0) -or" in helper and "Test-DefenseClawCodexWriterLockNamed -Path $statePath" in helper
    assert "% 2) -eq 0" not in helper


def test_a_refusal_whose_rollback_met_the_writer_again_is_named_once() -> None:
    body = _function_body(_text(), "Invoke-DefenseClawInstallLikeLifecycle")
    assert "$firstFailure.StartsWith('codex_state_unsettled: '" in body
    assert "$rollbackHeld.StartsWith('codex_state_unsettled: '" in body


def test_the_recoveries_that_start_the_services_keep_the_writer_deferral() -> None:
    text = _text()
    assert text.count("$codexWriterKept = Get-DefenseClawRollbackCodexWriterHolds") == 2
    assert text.count("Restore-DefenseClawRollbackCodexWriterHolds -Kept $codexWriterKept") == 2
    # The call that clears is rel's, untouched.
    assert text.count("Clear-DefenseClawRollbackDeferredHolds\n") >= 4


def test_every_rollback_readiness_assertion_defers_a_busy_writer() -> None:
    # Both rollbacks (the restore of a transaction and the restore that ends a
    # managed-hook teardown) end in this assertion, so the flag is set here and reset
    # whatever happens; the callers keep rel's text.
    text = _text()
    ready = _function_body(text, "Assert-DefenseClawRestoredTransactionReadyForActivation")
    flag = ready.index("$script:DefenseClawRollbackDeferBusyWriter = [bool](Test-DefenseClawStandaloneProfile)")
    call = ready.index("Assert-DefenseClawEnterpriseDeployment `\n")
    final = ready.index("$script:DefenseClawRollbackDeferBusyWriter = $false")
    assert flag < ready.index("try {", flag) < call < ready.index("finally {", call) < final < ready.index("return $true")
    for name in ("Restore-DefenseClawTransaction", "Restore-DefenseClawTransactionWithManagedHooksRollback"):
        assert "DefenseClawRollbackDeferBusyWriter" not in _function_body(text, name), name
    assert text.count("Assert-DefenseClawRestoredTransactionReadyForActivation `\n") == 2
    command = _function_body(text, "Invoke-DefenseClawCodexRequirementsCommand")
    gate = command.index("if ($script:DefenseClawRollbackDeferBusyWriter -and $Action -in @('verify', 'inspect')) {")
    assert command.index("Test-DefenseClawStandaloneProfile") < gate < command.index("New-DefenseClawCodexWriterBusyRefusal")
    assert "return $null" in command[gate : gate + 700]
    # Any other action inside the rollback meets the held form, which the recovery defers.
    refusal = _function_body(text, "New-DefenseClawCodexWriterBusyRefusal")
    assert refusal.index("if ($script:DefenseClawRollbackDeferBusyWriter) {") < refusal.index("$path = [string]$Layout.CodexManagedHooksStatePath")


def test_the_exit_code_is_the_held_rollback_convention_when_the_rollback_is_pending() -> None:
    go = GO.read_text(encoding="utf-8")
    start = go.index('case "codex_state_unsettled":')
    window = go[start : start + 900]
    assert "if result.TransactionPending && strings.Contains(message.Message, windowsEnterpriseUnsettledRollbackDeferredText) {" in window
    assert "return enterprisestatus.WindowsExitBusy" in window
    assert (
        "(report.TransactionPending && windowsEnterpriseUnsettledRollbackDeferred(result.Errors[firstError:]))"
        in go
    )
    assert 'case "codex_state_held", "codex_requirements_held", "privileges_required", "guardian_state_held", "codex_state_unsettled":' in go


_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case, [int]$Standalone = 1)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Test-DefenseClawCodexWriterLockBusyMessage', 'New-DefenseClawCodexWriterBusyRefusal', 'Get-DefenseClawOptionalLayoutValue', 'Get-DefenseClawCodexManagedHooksWriterCounter', 'Test-DefenseClawRollbackHeldMessage', 'New-DefenseClawCodexWriterUnsettledHeldMessage', 'Test-DefenseClawGuardianProofDeferredByCodexWriter', 'Test-DefenseClawCodexWriterLockNamed', 'Get-DefenseClawRollbackCodexWriterHolds', 'Restore-DefenseClawRollbackCodexWriterHolds', 'Get-DefenseClawCodexRequirementsGuardProblem', 'Assert-DefenseClawCodexRequirementsPublishable', 'Clear-DefenseClawRollbackDeferredHolds', 'Assert-DefenseClawRestoredTransactionReadyForActivation', 'Invoke-DefenseClawManagedHooksTeardownCommand', 'ConvertTo-DefenseClawBoundedDiagnostic', 'Test-DefenseClawBusyWriterIsTheOnlyFailure', 'Test-DefenseClawRollbackCoverageDeferred', 'Get-DefenseClawHeldMessagePath', 'Add-DefenseClawRollbackDeferredHold', 'Assert-DefenseClawRollbackHoldsResolved')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing $name" }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$script:DefenseClawRollbackDeferredHolds = [Collections.Generic.List[string]]::new()
$script:DefenseClawRollbackCoverageDeferred = $false
$script:DefenseClawRollbackDeferBusyWriter = $false
$script:DefenseClawTeardownRollbackDeferBusy = $false
$script:DefenseClawTeardownRollbackDeferred = $false
$script:events = [Collections.Generic.List[string]]::new()
function Test-DefenseClawStandaloneProfile { [bool]$Standalone }
function Write-DefenseClawResilienceEvent { param([string]$Marker, [hashtable]$Fields) $script:events.Add($Marker + ': ' + $Fields['reason']) }
function Format-DefenseClawSetupAction { param([string]$Action) "Setup $Action" }
$script:Named = $true
function Get-DefenseClawCodexWriterHolderText { param([string]$Path) if ($script:Named) { 'the writer is writer.exe (pid 4242, account NT AUTHORITY\SYSTEM)' } else { 'no program this account can name has the writer lock open: the writer stopped in the middle of its transaction or runs as SYSTEM' } }
$state = Join-Path $Scratch '.defenseclaw-managed-hooks.state'
$lock = Join-Path $Scratch '.defenseclaw-managed-hooks.writer.lock'
function Set-Counter([int]$Size) { [IO.File]::WriteAllBytes($lock, [byte[]]::new($Size)) }
$policy = Join-Path $Scratch 'requirements.toml'
$layout = @{ CodexManagedHooksStatePath = $state; CodexMachinePolicyPath = $policy; CodexTargetEnabled = $true; ManagedHookContractCleanupReceiptPath = ''; ManifestPath = 'C:\\m'; ManagedHooksTeardownJournalPath = 'C:\\j' }
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
    'even-held' {
        Set-Counter 18
        $out.deferred = [bool](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
        $out.holds = @($script:DefenseClawRollbackDeferredHolds)
        $out.coverage = [bool]$script:DefenseClawRollbackCoverageDeferred
    }
    'hookless' {
        Set-Counter 19
        $out.messages = [ordered]@{}
        [IO.File]::WriteAllBytes($policy, [byte[]]@())
        $out.messages.empty = New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $layout
        [IO.File]::WriteAllText($policy, "allow_managed_hooks_only = true`n")
        $out.messages.nohook = New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $layout
        Remove-Item -LiteralPath $policy -Force
        $out.messages.missing = New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $layout
        [IO.File]::WriteAllText($policy, "[[hooks.SessionStart]]`ncommand = 'defenseclaw-hook.exe'`n")
        $out.messages.guarded = New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $layout
    }
    'codex-off' {
        # A deployment without a Codex target never says Codex is unguarded.
        Set-Counter 19
        $layoutOff = @{ CodexManagedHooksStatePath = $state; CodexMachinePolicyPath = $policy; CodexTargetEnabled = $false }
        [IO.File]::WriteAllBytes($policy, [byte[]]@())
        $out.message = New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $layoutOff
        $layoutMissing = @{ CodexManagedHooksStatePath = $state; CodexMachinePolicyPath = $policy }
        $out.messageMissing = New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $layoutMissing
        [IO.File]::WriteAllBytes($policy, [byte[]]@())
        $out.messageOn = New-DefenseClawCodexWriterUnsettledHeldMessage -Layout $layout
    }
    'teardown' {
        # The managed-hook teardown rollback of a transaction meets a Codex writer that holds the lock.
        Set-Counter 19
        $script:probe = $null
        function Assert-DefenseClawAdministrator { }
        function Invoke-DefenseClawGatewayCommand { param([Parameter(ValueFromRemainingArguments)]$Rest) $script:probe }
        $busyJson = '{"schema_version":4,"action":"rollback","ok":false,"error":"timed out waiting 10s for Codex machine policy lock","error_code":"writer_lock_busy","results":[]}'
        $oldJson = '{"schema_version":4,"action":"rollback","ok":false,"error":"timed out waiting 10s for Codex machine policy lock","results":[]}'
        $otherJson = '{"schema_version":4,"action":"rollback","ok":false,"error":"Codex machine policy is not clean after teardown rollback","results":[]}'
        $joinedJson = '{"schema_version":4,"action":"rollback","ok":false,"error":"restore pre-rollback Claude policy after Codex failure: access denied\ntimed out waiting 10s for Codex machine policy lock","results":[]}'
        $lockViolationJson = '{"schema_version":4,"action":"rollback","ok":false,"error":"open Codex machine policy lock: The process cannot access the file because another process has locked a portion of the file.","results":[]}'
        function Try-Rollback([string]$Json, [bool]$Flag) {
            $script:probe = [pscustomobject]@{ exit_code = 1; output = @($Json) }
            $script:DefenseClawTeardownRollbackDeferred = $false
            $script:DefenseClawTeardownRollbackDeferBusy = $Flag
            Clear-DefenseClawRollbackDeferredHolds
            $threw = ''; $returned = 'none'
            try { $returned = [string]@(Invoke-DefenseClawManagedHooksTeardownCommand -Layout $layout -GatewayServiceName gw -GuardianServiceName gd -Action rollback).Count } catch { $threw = $_.Exception.Message }
            [ordered]@{ threw = $threw; returned = $returned; deferred = [bool]$script:DefenseClawTeardownRollbackDeferred; holds = @($script:DefenseClawRollbackDeferredHolds) }
        }
        $out.byCode = Try-Rollback $busyJson $true
        $out.byText = Try-Rollback $oldJson $true
        $out.flagOff = Try-Rollback $busyJson $false
        $out.other = Try-Rollback $otherJson $true
        $out.joined = Try-Rollback $joinedJson $true
        $out.lockViolation = Try-Rollback $lockViolationJson $true
    }
    'even' {
        $script:Named = $false
        Set-Counter 18
        $out.deferred = [bool](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
        $out.holds = @($script:DefenseClawRollbackDeferredHolds)
        $out.coverage = [bool]$script:DefenseClawRollbackCoverageDeferred
    }
    'no-lock' {
        $script:Named = $false
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
    'busy-in-rollback' {
        # The flag a rollback's readiness assertion sets: the refusal is the rollback's own held form.
        Set-Counter 18
        $script:DefenseClawRollbackDeferBusyWriter = $true
        $out.refusal = New-DefenseClawCodexWriterBusyRefusal -Layout $layout -Action 'reconcile' -Detail 'timed out waiting 10s for Codex machine policy lock'
        $out.held = [bool](Test-DefenseClawRollbackHeldMessage -Message $out.refusal)
    }
    'ready' {
        # The readiness assertion both rollbacks end in (the restore of a transaction and the restore that ends
        # a managed-hook teardown): the flag is set while the deployment check runs, and reset whatever happens.
        function Get-DefenseClawTransactionServiceStates { param($Services, $GatewayServiceName, $GuardianServiceName) @{ gw = [pscustomobject]@{ existed = $true }; gd = [pscustomobject]@{ existed = $true }; br = [pscustomobject]@{ existed = $false }; en = [pscustomobject]@{ existed = $true } } }
        function Get-DefenseClawCMIDBrokerServiceName { param($GatewayServiceName) 'br' }
        function Get-DefenseClawEnumeratorServiceName { param($GuardianServiceName) 'en' }
        function Test-DefenseClawTransactionBrokerTopology { param($Layout) $false }
        function Test-DefenseClawServiceExists { param($Name) $false }
        function Get-DefenseClawEarlyHookField { param($Record, $Name) '' }
        function Get-DefenseClawTransactionGatewayAccount { param($Snapshot) 'acct' }
        $script:seen = [Collections.Generic.List[string]]::new()
        $script:boom = $false
        function Assert-DefenseClawEnterpriseDeployment { param([Parameter(ValueFromRemainingArguments)]$Rest) $script:seen.Add([string]$script:DefenseClawRollbackDeferBusyWriter); if ($script:boom) { throw 'deployment check failed' } }
        $snap = [pscustomobject]@{ services = @(); gateway_service = 'gw'; guardian_service = 'gd' }
        $out.result = [bool](Assert-DefenseClawRestoredTransactionReadyForActivation -Snapshot $snap -Layout $layout)
        $out.flagDuring = @($script:seen)
        $out.flagAfter = [bool]$script:DefenseClawRollbackDeferBusyWriter
        $script:boom = $true
        $threw = ''
        try { [void](Assert-DefenseClawRestoredTransactionReadyForActivation -Snapshot $snap -Layout $layout) } catch { $threw = $_.Exception.Message }
        $out.threw = $threw
        $out.flagAfterThrow = [bool]$script:DefenseClawRollbackDeferBusyWriter
        $out.flagDuringAll = @($script:seen)
    }
    'forward-refusal' {
        $refusal = 'codex_state_unsettled: the Codex writer transaction counter next to X stayed at 3 (odd: a transaction is open) for 30 seconds (the writer is writer.exe (pid 4242)), so the Codex managed-hooks state could not be judged and this run stopped (an install, repair, ensure or upgrade that had started is rolled back, an upgrade to the release it came from; a verify changes nothing). Next step: run Setup /repair again once no Codex writer is running'
        $out.held = [bool](Test-DefenseClawRollbackHeldMessage -Message $refusal)
    }
    'keep' {
        Set-Counter 19
        [void](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
        Add-DefenseClawRollbackDeferredHold -Message 'hook_in_use: x has C:\h.exe, the installed hook, open'
        $kept = Get-DefenseClawRollbackCodexWriterHolds
        Clear-DefenseClawRollbackDeferredHolds
        Restore-DefenseClawRollbackCodexWriterHolds -Kept $kept
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


def test_a_named_holder_defers_the_proof_with_an_even_counter(tmp_path: Path) -> None:
    # GAP-0999 review: an antivirus scanner or a program that does not follow the
    # counter protocol holds the writer lock with the counter even; the guardian
    # still cannot publish, so the proof is deferred the same way.
    result = _run(tmp_path, "even-held")
    assert result["deferred"] is True and result["coverage"] is True, result
    (hold,) = result["holds"]
    assert hold.startswith("codex_state_unsettled: "), result
    assert "the writer is writer.exe (pid 4242, account NT AUTHORITY\\SYSTEM)" in hold, result
    assert "stayed at 18 (even, but a writer holds the lock or keeps changing it" in hold, result
    assert "run Setup /repair" in hold and "FORCE" not in hold, result


def test_a_hookless_requirements_file_is_said_plainly_in_the_deferral(tmp_path: Path) -> None:
    # GAP-1001 wording: nothing guards Codex until the policy is published again.
    messages = _run(tmp_path, "hookless")["messages"]
    for key, what in (
        ("empty", "requirements.toml is empty, so nothing guards Codex until the policy is published again: run Setup /repair as an administrator"),
        ("nohook", "does not carry the DefenseClaw managed hook (it has no [[hooks.<Event>]] entry"),
        ("missing", "requirements.toml does not exist, so nothing guards Codex until the policy is published again"),
    ):
        assert "Codex is not guarded right now: " in messages[key], messages[key]
        assert what in messages[key], messages[key]
    assert "Codex is not guarded" not in messages["guarded"], messages["guarded"]
    assert messages["guarded"].startswith("codex_state_unsettled: ")


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


def test_the_teardown_rollback_defers_a_busy_codex_writer_only_where_the_rollback_asks(tmp_path: Path) -> None:
    # GAP-0999 review round 2: the hidden managed-hook teardown rollback runs BEFORE the readiness
    # assertion and meets the writer lock first (restoreWindowsCodexManagedHooks under the lock).
    result = _run(tmp_path, "teardown")
    for key in ("byCode", "byText"):
        got = result[key]
        assert got["threw"] == "" and got["deferred"] is True, (key, result)
        (hold,) = got["holds"]
        assert hold.startswith("codex_state_unsettled: ") and "the rollback left that state as it is" in hold, (key, result)
        assert "The managed-hook teardown of the uninstall was not fully rolled back" in hold, (key, result)
        # What the Go rollback already restored (selectors, per-user enrollments) is said apart from what stays as the uninstall left it.
        assert "runtime selectors and the per-user enrollments it removed are back" in hold, (key, result)
        assert "Claude Code, Cursor and Codex machine-policy hooks stay as the uninstall left them" in hold, (key, result)
        assert "run Setup /repair" in hold and "FORCE" not in hold, (key, result)
    # Not asked for (a forward step, Secure Client) or not a busy writer: the failure stands.
    # An old gateway's open-time LOCK_VIOLATION text is the same cause.
    assert result["lockViolation"]["deferred"] is True and result["lockViolation"]["threw"] == "", result
    # A busy writer next to another failure (a compensation that failed too) is not a writer-only
    # failure: thrown as before, nothing deferred.
    for key in ("flagOff", "other", "joined"):
        got = result[key]
        assert got["threw"].startswith("managed-hook teardown rollback failed: "), (key, result)
        assert got["deferred"] is False and got["holds"] == [], (key, result)


def test_a_deployment_without_codex_never_says_codex_is_unguarded(tmp_path: Path) -> None:
    result = _run(tmp_path, "codex-off")
    assert "Codex is not guarded" not in result["message"], result
    assert "Codex is not guarded" not in result["messageMissing"], result
    assert "Codex is not guarded right now" in result["messageOn"], result


def test_the_teardown_rollback_call_defers_and_keeps_the_receipt_for_the_repair() -> None:
    text = _text()
    restore = _function_body(text, "Restore-DefenseClawTransactionWithManagedHooksRollback")
    flag = restore.index("$script:DefenseClawTeardownRollbackDeferBusy = [bool](Test-DefenseClawStandaloneProfile)")
    call = restore.index("-Action rollback)")
    assert flag < restore.index("try {", flag) < restore.index("Invoke-DefenseClawManagedHooksTeardownCommand `\n", flag) < call
    assert call < restore.index("finally {", call) < restore.index("if ($script:DefenseClawTeardownRollbackDeferred) {", call)
    # A deferred teardown rollback must not retire the prepared receipt (the repair needs it).
    keep = restore.index("$journalPreserved = $false", call)
    assert keep < restore.index("$rollbackReceipt = Get-DefenseClawManagedHookContractCleanupReceipt")
    wrapper = _function_body(text, "Invoke-DefenseClawManagedHooksTeardownCommand")
    gate = wrapper.index("if ($Action -ceq 'rollback' -and $script:DefenseClawTeardownRollbackDeferBusy -and")
    assert wrapper.index("Test-DefenseClawStandaloneProfile", gate) < wrapper.index("return $null", gate) < wrapper.index('throw "managed-hook teardown $Action failed: $detail"')
    assert "error_code" in wrapper[gate - 400 : gate] and "Test-DefenseClawBusyWriterIsTheOnlyFailure" in wrapper[gate : gate + 400]
    # The flag that says a teardown rollback was deferred is reset once it has been used.
    assert restore.index("$script:DefenseClawTeardownRollbackDeferred = $false", keep) < restore.index("$rollbackReceipt = Get-DefenseClawManagedHookContractCleanupReceipt")


def test_the_readiness_assertion_sets_the_flag_for_the_check_and_always_resets_it(tmp_path: Path) -> None:
    result = _run(tmp_path, "ready")
    assert result["result"] is True and result["flagDuring"] == ["True"], result
    assert result["flagAfter"] is False, result
    # A failed deployment check still resets it (the rollback that follows must not defer).
    assert result["threw"] == "deployment check failed", result
    assert result["flagDuringAll"] == ["True", "True"] and result["flagAfterThrow"] is False, result


def test_secure_client_readiness_assertion_never_sets_the_flag(tmp_path: Path) -> None:
    result = _run(tmp_path, "ready", standalone=False)
    assert result["flagDuring"] == ["False"] and result["flagAfter"] is False, result


def test_a_busy_writer_inside_a_rollback_is_the_rollbacks_held_form(tmp_path: Path) -> None:
    result = _run(tmp_path, "busy-in-rollback")
    assert result["held"] is True, result
    assert result["refusal"].startswith("codex_state_unsettled: "), result
    assert "the rollback left that state as it is" in result["refusal"], result
    assert "FORCE" not in result["refusal"], result


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
    # Inside a rollback the recovery's busy answer is the rollback's own held form, which
    # the recovery's catch (rel's) defers.
    deployment = _function_body(text, "Assert-DefenseClawEnterpriseDeployment")
    assert "Test-DefenseClawRollbackHeldMessage -Message ([string]$_.Exception.Message)" in deployment


def test_a_rollback_that_keeps_a_guarded_requirements_file_says_so_in_the_failed_run() -> None:
    # GAP-1001 review D2: the failed run names the file the rollback kept.
    text = _text()
    restore = _function_body(text, "Restore-DefenseClawTransaction")
    assert "$script:DefenseClawRollbackKeptGuardedNote = ''" in restore
    note = restore.index("$script:DefenseClawRollbackKeptGuardedNote = \"The Codex requirements.toml was not put back")
    assert note < restore.index("continue", note) < restore.index("-Source $backup", note)
    install = _function_body(text, "Invoke-DefenseClawInstallLikeLifecycle")
    keep = install.index("if ($script:DefenseClawRollbackKeptGuardedNote -ne '') {")
    assert "$operationError.Exception.Message + '. ' + $script:DefenseClawRollbackKeptGuardedNote" in install[keep : keep + 300]
    assert keep < install.index("throw $operationError", keep)
