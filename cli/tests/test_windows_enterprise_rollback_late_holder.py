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
    assert len(sites) == 5, len(sites)
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
    assert restore.rindex("Assert-DefenseClawRollbackHoldsResolved") > restore.index("Start-DefenseClawTransactionServices")
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
    # Set in one place: the recovery's held republish of the Codex requirements.
    assert text.count("$script:DefenseClawRollbackCoverageDeferred = $true") == 1
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
