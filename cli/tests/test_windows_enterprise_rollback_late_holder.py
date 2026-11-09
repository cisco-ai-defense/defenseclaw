r"""GAP-0947 (r109): a Codex holder that arrives during the automatic rollback
of a failed Setup /ensure (after the pre-stop gate) used to end the run 1603
lifecycle_error with the four services stopped, the holder not named and the
advice /uninstall FORCE=1. The rollback now leaves the file it cannot put back,
names the holder, puts everything else back and starts the restored services,
and ends with the retryable held code (exit 1618) and the transaction still
pending; /repair finishes it. Standalone only: Secure Client keeps its
rollback as it was.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"


def _text() -> str:
    return MODULE.read_text(encoding="utf-8")


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


def test_the_held_message_names_the_holder_and_points_at_repair() -> None:
    body = _function_body(_text(), "New-DefenseClawRollbackHeldMessage")
    # By process and id; a holder Windows reports without an id is named by the hint.
    assert "process id {1}" in body
    assert "it may run as SYSTEM, so no process id is available" in body
    assert "Format-DefenseClawSetupAction -Action '/repair'" in body
    assert "exit 1618" in body and "the transaction is still pending" in body
    # Never the forced uninstall.
    assert "FORCE" not in body and "uninstall" not in body.lower()
    codex = _function_body(_text(), "New-DefenseClawCodexFileHeldMessage")
    assert "'codex_requirements_held'" in codex and "'codex_state_held'" in codex
    hook = _function_body(_text(), "New-DefenseClawHookHeldMessage")
    assert "-Code 'hook_in_use'" in hook


def test_every_deferral_is_standalone_only() -> None:
    text = _text()
    sites = [m.start() for m in re.finditer(r"Add-DefenseClawRollbackDeferredHold -Message", text)]
    # The definition is a function, not a call.
    sites = [s for s in sites if not text[max(0, s - 40) : s].rstrip().endswith("function")]
    # GAP-0977 added the eighth: a guardian state file a holder keeps the guardian from publishing.
    assert len(sites) == 8, len(sites)
    for site in sites:
        window = text[max(0, site - 1700) : site]
        assert "Test-DefenseClawStandaloneProfile" in window, text[site - 200 : site + 100]


def test_a_blocked_put_back_is_left_and_the_rollback_carries_on() -> None:
    restore = _function_body(_text(), "Restore-DefenseClawTransaction")
    # Put-back, access-list write and removal each defer and move to the next file.
    assert restore.count("Add-DefenseClawRollbackDeferredHold") == 3
    for needle in (
        "-Why 'open without delete sharing, so the rollback could not put it back')\n                    continue",
        "-Why 'open without delete sharing, so the rollback could not remove it')\n                    continue",
        "Add-DefenseClawRollbackDeferredHold -Message ([string]$_.Exception.Message)\n                        continue",
    ):
        assert needle in restore, needle
    # The list starts empty, and the run ends with the held code after the
    # services were started (not before).
    assert restore.index("Clear-DefenseClawRollbackDeferredHolds") < restore.index("$snapshotCertificationProperty")
    assert restore.rindex("Assert-DefenseClawRollbackHoldsResolved") > restore.index(
        "Start-DefenseClawTransactionServices"
    )
    assert "if (-not $DeferServiceRestart) {\n        # GAP-0947" in restore


def test_the_deferred_restart_path_ends_with_the_held_code_too() -> None:
    wrapper = _function_body(_text(), "Restore-DefenseClawTransactionWithManagedHooksRollback")
    end = wrapper.rindex("Assert-DefenseClawRollbackHoldsResolved")
    assert end > wrapper.index("Start-DefenseClawTransactionServices")
    assert end < wrapper.rindex("return $snapshot")


def test_the_recovery_republish_that_a_holder_blocks_does_not_keep_the_services_down() -> None:
    body = _function_body(_text(), "Assert-DefenseClawEnterpriseDeployment")
    gate = body.index("if ($RepairRecoveredCodexRequirements -and $ServicingTransaction -and")
    catch = body.index("Test-DefenseClawRollbackHeldMessage", gate)
    verify = body.index("-Action $(if ($codexTargetEnabled) { 'verify' } else { 'inspect' }))")
    assert gate < catch < verify
    assert "$codexRequirementsDeferred = $true" in body[catch:verify]
    # Only the held code defers; any other failure still stops the recovery.
    assert "throw\n            }" in body[catch:verify]
    assert "if (-not $codexRequirementsDeferred) {" in body[catch:verify]


def test_the_previous_hook_that_a_holder_blocks_is_deferred_after_the_services_run() -> None:
    body = _function_body(_text(), "Restore-DefenseClawSnapshotHookAfterActivation")
    assert "Add-DefenseClawRollbackDeferredHold -Message (New-DefenseClawHookHeldMessage -Layout $Layout)" in body
    assert body.index("Test-DefenseClawStandaloneProfile") < body.index("New-DefenseClawHookHeldMessage")
    # The digest check still runs for a hook that went back.
    assert body.index("return\n        }\n        throw") < body.index("restored prior hook digest does not match")


def test_a_failed_run_whose_rollback_met_a_holder_ends_with_the_held_code_and_the_original_failure() -> None:
    text = _text()
    start = text.index("# GAP-0947: a program that arrived during the rollback holds a")
    block = text[start : start + 900]
    assert "(Test-DefenseClawStandaloneProfile)" in text[start - 250 : start]
    assert "Test-DefenseClawRollbackHeldMessage" in text[start - 250 : start]
    assert ". This $Action had failed first: " in block
    # Secure Client strict ancestors keeps its combined message, ahead of this.
    assert text.rindex("rollback also failed and pending recovery was retained", 0, start) > start - 500


def test_the_second_holder_does_not_cost_another_full_wait() -> None:
    body = _function_body(_text(), "Open-DefenseClawCodexRollbackHold")
    assert "[Math]::Min($TimeoutSeconds, 5)" in body
    assert body.index("DefenseClawRollbackDeferredHolds.Count -gt 0") < body.index("$deadline")


def test_the_guardian_coverage_proof_is_deferred_only_for_a_republish_a_holder_blocked() -> None:
    text = _text()
    # Set in three places, all in the rollback: the held republish of the Codex requirements, the held state check, and (GAP-0977) a held
    # guardian state file, which the guardian cannot publish over.
    assert text.count("$script:DefenseClawRollbackCoverageDeferred = $true") == 3
    deployment = _function_body(text, "Assert-DefenseClawEnterpriseDeployment")
    assert "$script:DefenseClawRollbackCoverageDeferred = $true" in deployment
    check = _function_body(text, "Test-DefenseClawRollbackCoverageDeferred")
    # Needs a deferred hold, and the standalone profile.
    assert "DefenseClawRollbackDeferredHolds.Count -gt 0" in check and "Test-DefenseClawStandaloneProfile" in check
    start = _function_body(text, "Start-DefenseClawTransactionServices")
    gate = start.index("if (Test-DefenseClawRollbackCoverageDeferred) {")
    assert gate < start.index("Wait-DefenseClawFreshGuardianReconcile")
    assert "-GuardianCoverageDeferred:(Test-DefenseClawRollbackCoverageDeferred)" in start
    ready = _function_body(text, "Wait-DefenseClawEnterpriseReadiness")
    assert "[switch]$GuardianCoverageDeferred" in ready
    # The gateway must still be ready; the guardian (which exits on the edited
    # policy) is not waited for.
    assert "$gatewayReady -and $GuardianCoverageDeferred" in ready
    assert "$guardianReady = $true" in ready[ready.index("$GuardianCoverageDeferred) {") :][:700]
    # A finished or cleared rollback leaves nothing deferred.
    clear = _function_body(text, "Clear-DefenseClawRollbackDeferredHolds")
    assert "DefenseClawRollbackCoverageDeferred = $false" in clear
    assert "Clear-DefenseClawRollbackDeferredHolds" in _function_body(text, "Assert-DefenseClawRollbackHoldsResolved")


def test_the_recovery_names_a_held_codex_state_file_before_and_after_the_reconcile_fails() -> None:
    text = _text()
    probe = _function_body(text, "Get-DefenseClawBlockedCodexStatePath")
    assert (
        "Get-DefenseClawOptionalLayoutValue -Layout $Layout -Name CodexManagedHooksStatePath" in probe
        and "Get-DefenseClawCodexManagedHooksStateWriterCopyList" in probe
    )
    assert "Test-DefenseClawFileReadBlocked" in probe and "Test-DefenseClawFileDeleteBlocked" in probe
    body = _function_body(text, "Repair-DefenseClawRecoveredCodexRequirements")
    assert body.count("Get-DefenseClawBlockedCodexStatePath -Layout $Layout") == 2
    first = body.index("Get-DefenseClawBlockedCodexStatePath -Layout $Layout")
    # Before anything is saved or written, and again before the rebuild.
    assert (
        first
        < body.index("[IO.FileMode]::CreateNew")
        < body.rindex("Get-DefenseClawBlockedCodexStatePath -Layout $Layout")
    )
    assert body.rindex("Get-DefenseClawBlockedCodexStatePath -Layout $Layout") < body.index(
        "Get-DefenseClawRecordedCodexRequirementsPreimage"
    )


def test_a_held_codex_state_copy_defers_the_state_check_of_a_rollback() -> None:
    body = _function_body(_text(), "Assert-DefenseClawEnterpriseDeployment")
    init = body.index("$codexRequirementsDeferred = $false")
    check = body.index("Assert-DefenseClawCodexManagedHooksStateFile -Layout $Layout")
    catch = body.index("Get-DefenseClawBlockedCodexStatePath -Layout $Layout", check)
    # One init, ahead of the state check; only a servicing rollback on the
    # standalone profile that finds a holder defers; anything else rethrows.
    assert body.count("$codexRequirementsDeferred = $false") == 1 and init < check < catch
    window = body[check:catch]
    assert "$RepairRecoveredCodexRequirements -and $ServicingTransaction" in window
    assert "Test-DefenseClawStandaloneProfile" in window
    assert "if ($blockedState -eq '') {\n                throw" in body[catch : catch + 300]
    # The republish and the Codex verify are skipped once the state check deferred.
    gate = body.index("if ($RepairRecoveredCodexRequirements -and $ServicingTransaction -and", catch)
    assert "-not $codexRequirementsDeferred) {" in body[gate : gate + 300]
    assert "if (-not $codexRequirementsDeferred) {" in body[gate:]


def test_a_forward_run_replaces_a_hand_edited_requirements_file_instead_of_failing() -> None:
    """GAP-0955: the recovery that a rollback ran (GAP-0802) also runs in the
    forward reconcile, so one /ensure ends rc 0 for a machine it repaired."""
    text = _text()
    body = _function_body(text, "Invoke-DefenseClawCodexRequirementsReconcileOrRecover")
    assert body.index("-Action reconcile") < body.index("$reconcileFailure = $_")
    assert body.index("Test-DefenseClawStandaloneProfile") < body.index("Repair-DefenseClawRecoveredCodexRequirements")
    # A failure the recovery did not explain is the failure of the run.
    assert body.index("Repair-DefenseClawRecoveredCodexRequirements") < body.index("throw $reconcileFailure")
    assert "DefenseClawRecoveredCodexRequirementsNotes).Count -eq $recoveredBefore" in body
    # The caller runs the ACLs and the checks after it, unchanged.
    call = text.index("Invoke-DefenseClawCodexRequirementsReconcileOrRecover `\n")
    after = text[call : call + 900]
    assert after.index("Set-DefenseClawManagedAcls") < after.index(
        "Assert-DefenseClawCodexMachinePolicyFile -Layout $Layout"
    )
    assert "Set-DefenseClawManagedAcls" in after


def test_the_early_hook_put_back_defers_a_held_hook_after_the_services_run() -> None:
    """Review S1: Restore-DefenseClawEarlyHook names the holder (hook_in_use, 1618)
    and the recovery ends there with the intent pending."""
    text = _text()
    body = _function_body(text, "Restore-DefenseClawEarlyHook")
    assert "Add-DefenseClawRollbackDeferredHold -Message (New-DefenseClawHookHeldMessage -Layout $Layout)" in body
    assert body.index("Test-DefenseClawStandaloneProfile") < body.index("New-DefenseClawHookHeldMessage")
    # Both standalone callers (after the services start) end on the hold list;
    # the Secure Client call before the start is unchanged.
    assert text.count("Restore-DefenseClawEarlyHook `\n") == 4
    for marker in (
        "-TransactionDirectory $directory\n                Assert-DefenseClawRollbackHoldsResolved",
        "-TransactionDirectory $recordedDirectory\n        # A held hook ends the recovery here, named, with the intent pending.\n        Assert-DefenseClawRollbackHoldsResolved",
    ):
        assert marker in text, marker
    assert "$heldRestart = [string]$_.Exception.Message" in text


def test_the_result_says_the_guardian_was_not_proven_and_names_each_file_once() -> None:
    """Review S2 and S6."""
    text = _text()
    done = _function_body(text, "Assert-DefenseClawRollbackHoldsResolved")
    assert done.index("Test-DefenseClawRollbackCoverageDeferred") < done.index("Clear-DefenseClawRollbackDeferredHolds")
    assert "The guardian's coverage was not proven by this rollback" in done
    add = _function_body(text, "Add-DefenseClawRollbackDeferredHold")
    assert "Get-DefenseClawHeldMessagePath" in add
    block = text[text.index("$rollbackHeld = [string]$_.Exception.Message") :][:900]
    assert "throw $rollbackHeld" in block and "This $Action had failed first: " in block


# GAP-0977 (r109): a guardian state file a holder keeps the guardian from
# publishing. The transaction found it before it stopped anything, names it
# when the fresh-coverage proof times out, and a rollback that meets it defers
# the guardian proof like the Codex files, so the restored services run and the
# run ends with the held code (exit 1618) and the transaction pending.


def test_a_guardian_state_hold_is_found_before_anything_stops() -> None:
    text = _text()
    transaction = _function_body(text, "New-DefenseClawTransaction")
    gate = transaction.index("Assert-DefenseClawGuardianStateNotHeld -Layout $Layout")
    assert gate < transaction.index("$codexReadHolds = $null")
    assert gate < transaction.index("New-DefenseClawDirectory -Path $directory")
    condition = "if ((Test-DefenseClawStandaloneProfile) -and $PriorDeploymentActive -and -not $SkipRedactionKeySnapshot) {"
    assert transaction.rindex(condition, 0, gate) > transaction.index("$codexReadHolds = $null") - 1200
    assert "-Phase Gate" in _function_body(text, "Assert-DefenseClawGuardianStateNotHeld")
    # The class is the critical files only (the others did not stop a repair when held),
    # and never a file a standard account can open (N2). The CLI list is the same four.
    files = _function_body(text, "Get-DefenseClawGuardianStateFiles")
    for needle in ("'protected_targets.json', 'activation.json', 'user-cleanup.json'", "hook_guardian_state.json", "Test-DefenseClawGuardianStateFileUserReadable"):
        assert needle in files, needle
    for gone in ("hook_guardian_*.json", "ManifestPath", "-Filter", "off-roster"):
        assert gone not in files, gone
    go = (ROOT / "internal" / "cli" / "windows_enterprise_guardian_state_held_windows.go").read_text(encoding="utf-8")
    assert "[]string{managed.HookGuardianAuthorizationFile, hookGuardianActivationFile, managed.HookGuardianUserCleanupFile}" in go
    assert "[]string{hookGuardianStateFile}" in go and "windowsEnterpriseGuardianStateUserReadable(path)" in go
    readable = _function_body(text, "Test-DefenseClawGuardianStateFileUserReadable")
    for sid in ("S-1-5-32-545", "S-1-5-11", "S-1-1-0", "S-1-5-4"):
        assert sid in readable, sid
    # S-H2: an uninstall or purge transaction is not held up by it.
    hold = _function_body(text, "Get-DefenseClawGuardianStateHold")
    assert "Test-DefenseClawStandaloneProfile" in hold and "Test-DefenseClawFileDeleteBlocked" in hold


def test_the_fresh_coverage_wait_names_a_guardian_state_hold() -> None:
    wait = _function_body(_text(), "Wait-DefenseClawFreshGuardianReconcile")
    held = wait.index("Get-DefenseClawGuardianStateHold -Layout $Layout")
    assert wait.index('$guardianLog = "the guardian log is') < held
    # Before every one of the three timeouts that follow.
    assert held < wait.index("LocalSystem guardian did not publish fresh required coverage: the hook guardian process")
    assert "-Phase Activation" in wait[held : held + 400]


def test_a_rollback_defers_the_guardian_proof_for_a_guardian_state_hold() -> None:
    text = _text()
    start = _function_body(text, "Start-DefenseClawTransactionServices")
    assert start.index("Set-DefenseClawRollbackGuardianStateDeferral -Layout $Layout") < start.index(
        "if (Test-DefenseClawRollbackCoverageDeferred) {"
    )
    deferral = _function_body(text, "Set-DefenseClawRollbackGuardianStateDeferral")
    assert "Test-DefenseClawStandaloneProfile" in deferral[: deferral.index("Add-DefenseClawRollbackDeferredHold")]
    assert "-Phase Rollback" in deferral and "DefenseClawRollbackCoverageDeferred = $true" in deferral
    # The held code is a rollback-held message, and the path it names is found again.
    assert "guardian_state_held" in _function_body(text, "Test-DefenseClawRollbackHeldMessage")
    assert "the hook guardian" in _function_body(text, "Get-DefenseClawHeldMessagePath")
    # Fail closed kept: Secure Client has no such deferral, and the held run is pending, not covered.
    assert "-Code 'guardian_state_held'" in _function_body(text, "New-DefenseClawGuardianStateHeldMessage")


def test_a_holder_that_arrives_during_the_rollback_proof_is_resolved_not_thrown() -> None:
    text = _text()
    start = _function_body(text, "Start-DefenseClawTransactionServices")
    wait = start.index("Wait-DefenseClawFreshGuardianReconcile")
    resolve = start.index("Resolve-DefenseClawRollbackLateGuardianHold")
    assert wait < resolve < start.index("Test-DefenseClawRecoveryActivationDeferral")
    body = _function_body(text, "Resolve-DefenseClawRollbackLateGuardianHold")
    # Standalone only, the held code only, and a deferral that actually took hold.
    assert body.index("if (-not (Test-DefenseClawStandaloneProfile)") < body.rindex("Set-DefenseClawRollbackGuardianStateDeferral")
    assert "'^guardian_state_held: '" in body and "Test-DefenseClawRollbackCoverageDeferred" in body
    assert body.rindex("return $true") > body.index("Start-DefenseClawService -Name $GuardianServiceName")


def test_secure_client_sees_none_of_the_guardian_state_hold_inserts() -> None:
    """S-H4: the three shared functions that gained an insert keep Secure Client as it was."""
    text = _text()
    # New-DefenseClawTransaction: the gate sits behind the standalone test.
    transaction = _function_body(text, "New-DefenseClawTransaction")
    gate = transaction.index("Assert-DefenseClawGuardianStateNotHeld -Layout $Layout")
    assert "if ((Test-DefenseClawStandaloneProfile) -and $PriorDeploymentActive -and -not $SkipRedactionKeySnapshot) {" in transaction[:gate]
    # Wait-DefenseClawFreshGuardianReconcile: the hold lookup answers $null off the standalone profile.
    wait = _function_body(text, "Wait-DefenseClawFreshGuardianReconcile")
    assert wait.count("Get-DefenseClawGuardianStateHold") == 1
    hold = _function_body(text, "Get-DefenseClawGuardianStateHold")
    assert hold.index("Test-DefenseClawStandaloneProfile") < hold.index("Get-DefenseClawGuardianStateFiles")
    assert "return $null" in hold[: hold.index("Get-DefenseClawGuardianStateFiles")]
    # Start-DefenseClawTransactionServices: both inserts are standalone-only.
    start = _function_body(text, "Start-DefenseClawTransactionServices")
    assert "if (Test-DefenseClawStandaloneProfile) {\n                # GAP-0977" in start
    assert "Resolve-DefenseClawRollbackLateGuardianHold" in start
    assert "Test-DefenseClawStandaloneProfile" in _function_body(text, "Resolve-DefenseClawRollbackLateGuardianHold")
    assert "Test-DefenseClawStandaloneProfile" in _function_body(text, "Set-DefenseClawRollbackGuardianStateDeferral")
    # Nothing else in the module calls the new functions.
    for name in ("Assert-DefenseClawGuardianStateNotHeld", "Set-DefenseClawRollbackGuardianStateDeferral", "Resolve-DefenseClawRollbackLateGuardianHold"):
        assert len(re.findall(re.escape(name) + r" -", text)) <= 2, name
