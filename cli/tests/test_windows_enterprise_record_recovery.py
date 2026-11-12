# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0602, GAP-0603: a Setup-owned record another account can change is kept
aside and written again, never trusted in place.

The native smoke (enterprise-standalone-record-recovery-smoke.ps1) runs the
behavior; these checks pin where the module and the ensure planner call it.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
STANDALONE = ROOT / "internal" / "cli" / "windows_enterprise_standalone.go"


def _text() -> str:
    return MODULE.read_text(encoding="utf-8-sig")


def _function(text: str, name: str) -> str:
    match = re.search(r"^function " + re.escape(name) + r" \{\n(.*?)^\}\n", text, re.S | re.M)
    assert match, f"{name} not found"
    return match.group(1)


def test_repair_keeps_a_changed_record_aside_before_it_reads_the_record() -> None:
    text = _text()
    call = text.index("Invoke-DefenseClawStandaloneRecordRecovery `\n                -Layout $layout")
    rollback = text.index("Assert-DefenseClawRepairRollbackConfig `", call)
    assert call < rollback
    guard = text[text.rindex("if ($Action -eq 'Repair'", 0, call):call]
    assert "Test-DefenseClawStandaloneProfile" in guard


def test_recovery_acts_only_on_standalone_without_a_pending_transaction() -> None:
    body = _function(_text(), "Invoke-DefenseClawStandaloneRecordRecovery")
    guard = body[: body.index("$changed = [Collections.Generic.List[object]]::new()")]
    assert "-not (Test-DefenseClawStandaloneProfile)" in guard
    assert "$Layout.PendingPath" in guard
    # The deployment record and the attestation are the two records; the
    # deployment record is rebuilt whenever either is kept aside.
    assert "$Layout.MetadataPath" in body and "$Layout.AgentApplicationControlAttestationPath" in body
    assert "New-DefenseClawRebuiltDeploymentRecord" in body


def test_the_rebuild_is_checked_and_built_before_any_live_record_changes() -> None:
    body = _function(_text(), "Invoke-DefenseClawStandaloneRecordRecovery")
    ready = body.index("    Assert-DefenseClawMetadataRebuildReady `\n")
    names = body.index("= (Get-DefenseClawStandaloneKeptRecordPath")
    build = body.index("$deploymentValue = New-DefenseClawRebuiltDeploymentRecord")
    publish = body.index("Publish-DefenseClawRecordKeepingOld `\n")
    assert ready < names < build < publish
    # Nothing at a live name is renamed, moved or deleted by this function: the
    # old object is kept by the atomic step of Publish-..., so a record is in
    # place at every moment (review D1). The kept file is stamped after.
    assert "Move-Item" not in body and "Remove-Item" not in body
    # The stamp of a kept copy is a warning, not a stop: the repair transaction
    # that follows must run on the rebuilt record.
    assert body.index("    Complete-DefenseClawKeptRecordStamps -Layout $Layout\n    return", publish) > publish
    assert "Protect-DefenseClawKeptRecord" not in body
    complete = _function(_text(), "Complete-DefenseClawKeptRecordStamps")
    assert "Write-Warning" in complete
    # A later run finishes what an earlier one left.
    assert "Complete-DefenseClawKeptRecordStamps" in body and "Get-DefenseClawOrphanedKeptRecordRefusal" in body
    names_body = _function(_text(), "Get-DefenseClawStandaloneKeptRecordPath")
    assert "Set-DefenseClawPathAcl" not in names_body and "Move-Item" not in names_body
    repair = _function(_text(), "Repair-DefenseClawUnreadableDeploymentMetadata")
    assert "Assert-DefenseClawMetadataRebuildReady" in repair
    ready_body = _function(_text(), "Assert-DefenseClawMetadataRebuildReady")
    assert "Write-DefenseClawJsonAtomic" not in ready_body and "Move-Item" not in ready_body
    builder = _function(_text(), "New-DefenseClawRebuiltDeploymentRecord")
    assert "Write-DefenseClawJsonAtomic" not in builder and "Move-Item" not in builder


def test_an_uninstall_refusal_names_the_forced_way_out() -> None:
    gate = _function(_text(), "Assert-DefenseClawStandaloneContentTrusted")
    tail = gate[gate.rindex("throw $message") - 600 : gate.rindex("throw $message")]
    assert "$Scope -cne 'Lifecycle'" in tail and "/uninstall FORCE=1 PURGE=1" in tail


def test_publish_stamps_a_sibling_then_swaps_it_in_with_the_old_object_kept() -> None:
    names = _function(_text(), "Get-DefenseClawStandaloneKeptRecordPath")
    assert names.index("Get-DefenseClawPathAclVerdicts") < names.index("'{0}.rejected-")
    body = _function(_text(), "Publish-DefenseClawRecordKeepingOld")
    sibling = body.index('$temporary = "$Path.new.')
    stamp = body.index("Set-DefenseClawPathAcl -Path $temporary -Kind AdminFile")
    swap = body.index("Invoke-DefenseClawLaunchableFileSwap")
    # The new JSON has its administrator-only access list before it has the
    # live name; one swap puts it there and keeps the old object as Kept.
    assert sibling < stamp < swap
    assert "-Backup $Kept" in body and "-KeepReplacementAccess" in body
    # No step renames the live record away before the new one is built.
    assert body.index("Move-Item") > swap


def test_the_orphaned_kept_copy_is_named_by_status_and_finished_by_repair() -> None:
    text = _text()
    refusal = _function(text, "Get-DefenseClawOrphanedKeptRecordRefusal")
    assert "untrusted_record: " in refusal and "'/repair'" in refusal
    # A state an uninstall left behind (no service) is no refusal: an install
    # removes the copies, so nobody is sent to a purge that deletes data.
    assert "Test-DefenseClawDeploymentServicesRegistered" in refusal and "PURGE=1" not in refusal
    leftover = _function(_text(), "Remove-DefenseClawLeftoverKeptRecords")
    assert "Test-DefenseClawDeploymentServicesRegistered" in leftover and ".rejected-" in leftover
    install = _text().index("Remove-DefenseClawLeftoverKeptRecords `\n                -Layout $layout")
    assert "'Install', 'Upgrade'" in _text()[install - 400 : install]
    entry = text.index("Get-DefenseClawOrphanedKeptRecordRefusal -Layout $layout")
    guard = text[text.rindex("if ((Test-DefenseClawStandaloneProfile)", 0, entry) : entry]
    assert "'Status', 'Verify', 'Install', 'Upgrade', 'Reconcile'" in guard
    # Uninstall and Repair are not stopped by it.
    assert "'Uninstall'" not in guard and "'Repair'" not in guard


def test_readers_refuse_by_name_with_the_exact_commands() -> None:
    text = _text()
    metadata = _function(text, "Get-DefenseClawDeploymentMetadataOnce")
    assert "Format-DefenseClawUntrustedRecordRefusal -Path $Layout.MetadataPath" in metadata
    attestation = _function(text, "Get-DefenseClawAgentApplicationControlAttestation")
    assert attestation.index("Format-DefenseClawUntrustedRecordRefusal") < attestation.index("Assert-DefenseClawPathAcl")
    refusal = _function(text, "Format-DefenseClawUntrustedRecordRefusal")
    assert "untrusted_record: " in refusal
    assert "/setowner *S-1-5-32-544" in refusal and "/remove:g *" in refusal
    assert "'/repair'" in refusal


def test_the_process_mark_is_standalone_only_and_widens_only_the_content_drift_refusal() -> None:
    service = (ROOT / "internal" / "cli" / "windows_enterprise_service.go").read_text(encoding="utf-8")
    call = service.index("managed.MarkStandaloneLifecycleProcess()")
    guard = service[service.rindex("if windowsEnterpriseStandalone(opts) {", 0, call) : call]
    assert guard.count("{") == 1, "the mark must sit directly under the standalone check"
    # It ends with the action, so a process that runs several carries none over.
    assert service[call:].index("defer managed.UnmarkStandaloneLifecycleProcess()") < 200
    # Secure Client never marks the process; the mark is read only by the
    # content-drift refusal, not by the trust scope.
    trust = (ROOT / "internal" / "managed" / "trust_standalone_windows.go").read_text(encoding="utf-8")
    refusal = trust[trust.index("func StandaloneRefusesContentDrift() bool {") :]
    refusal = refusal[: refusal.index("\n}\n")]
    assert "windowsStandaloneTrustScope() || standaloneLifecycleProcess.Load()" in refusal
    scope = trust[trust.index("var windowsStandaloneTrustScope = func() bool {") :]
    assert "standaloneLifecycleProcess" not in scope[: scope.index("\n}\n")]


def test_the_token_and_acp_folders_are_refused_before_a_standalone_stamp() -> None:
    token = (ROOT / "internal" / "cli" / "enterprise_hooks_token_windows.go").read_text(encoding="utf-8")
    align = token[token.index("func alignEnterpriseWindowsTokenOwner(") :]
    align = align[: align.index("\n}\n")]
    assert align.index("managed.RefuseStandaloneInPlaceRepair(dir") < align.index("setEnterpriseWindowsRuntimeProtection(dir")
    assert align.index("managed.RefuseStandaloneInPlaceRepair(path") < align.index("setEnterpriseWindowsRuntimeProtection(path")
    acp = (ROOT / "internal" / "cli" / "enterprise_acp_owner_windows.go").read_text(encoding="utf-8")
    body = acp[acp.index("func alignEnterpriseACPCredentialOwner(") :]
    assert body.index("RefuseStandaloneInPlaceRepair(directory") < body.index("setEnterpriseWindowsRuntimeProtection(directory")
    assert body.index("RefuseStandaloneInPlaceRepair(file") < body.index("setEnterpriseWindowsRuntimeProtection(path")


def test_ensure_names_a_runtime_folder_another_account_can_write_before_it_plans() -> None:
    go = STANDALONE.read_text(encoding="utf-8")
    seam = go[go.index("var windowsEnterpriseRuntimeFolderRefusal = func() string {") :]
    seam = seam[: seam.index("\n}\n")]
    assert '[]string{"hooks", "acp"}' in seam and "managed.RefuseStandaloneInPlaceRepairAs(" in seam
    call = go.index("windowsEnterpriseRuntimeFolderRefusal(); refusal != \"\"")
    assert go.rindex("noteWindowsEnterpriseEnsureDriftRepairs(result, driftRepaired, driftAtStart)", 0, call) > go.rindex("func runWindowsEnterpriseStandaloneEnsureOnce(", 0, call)
    assert "alreadyAppliedNeedsRepair := false" in go[call : call + 700], "the refusal must come before the plan"
    hook = (ROOT / "internal" / "cli" / "windows_enterprise_hookruntime_windows.go").read_text(encoding="utf-8")
    assert "errors.As(err, &refused)" in hook and "machine_policy_summary_untrusted" in go


def test_ensure_plans_a_repair_that_keeps_the_payload_for_a_changed_record() -> None:
    go = STANDALONE.read_text(encoding="utf-8")
    assert '"untrusted_record",' in go
    plan = go[go.index("func planWindowsEnterpriseEnsure("):]
    plan = plan[: plan.index("if status.TransactionPending")]
    assert 'strings.Contains(failure.Error(), "untrusted_record: ")' in plan
    assert "len(missingWindowsEnterpriseSources(opts)) == 0" in plan
    assert 'Reason: "untrusted_record"' in plan
    # The repair keeps this run's payload, which the rebuild re-records from.
    assert 'plan.Reason != "verify_failed" && plan.Reason != "untrusted_record"' in go


def test_a_rebuilt_record_is_marked_and_its_rollback_is_judged_by_its_artifacts() -> None:
    """GAP-0994: the rebuilt record cannot carry the evidence the full assertion asks
    for, so a rollback to it (services down, transaction pending) could not finish."""
    text = _text()
    builder = _function(text, "New-DefenseClawRebuiltDeploymentRecord")
    assert "record_rebuilt_by_setup = $true" in builder
    assert "managed_hooks_activation" not in builder
    marker = _function(text, "Test-DefenseClawRebuiltDeploymentRecord")
    assert "managed_hooks_activation" in marker, "a record with evidence is never called rebuilt"
    assertion = _function(text, "Assert-DefenseClawEnterpriseDeployment")
    early = assertion[assertion.index("if ($RollbackRestore -and (Test-DefenseClawStandaloneProfile)") :]
    early = early[: early.index("        return\n    }") + 20]
    assert "Test-DefenseClawRebuiltDeploymentRecord -Metadata $metadata" in early
    assert "Assert-DefenseClawRebuiltRecordArtifacts -Layout $Layout -Metadata $metadata" in early
    # Identity is checked first, the evidence check stays for every other caller.
    identity = assertion.index("Assert-DefenseClawMetadataIdentity `\n")
    assert identity < assertion.index("if ($RollbackRestore -and (Test-DefenseClawStandaloneProfile)")
    assert assertion.index("if ($RollbackRestore -and (Test-DefenseClawStandaloneProfile)") < assertion.index(
        "deployment metadata is missing protected managed-hook activation evidence"
    )


def test_the_guardian_is_made_to_publish_again_before_the_transaction_opens() -> None:
    """GAP-0994: the classification of a record with no activation evidence reads the
    Guardian's three records; the transaction stops every service before it, and
    nothing can publish them again after that."""
    text = _text()
    opens = text.index("    $snapshot = New-DefenseClawTransaction `\n")
    heal = text.rindex("Resolve-DefenseClawGuardianPublicationBeforeTransaction `\n", 0, opens)
    assert text.rindex("if ($priorDeploymentActive -and $null -eq $priorManagedHooksActivation -and", 0, heal) > opens - 900
    guard = text[text.rindex("if ($priorDeploymentActive", 0, heal) : heal]
    assert "Test-DefenseClawStandaloneProfile" in guard and "$recoverCommittedManagedHooksLifecycle" in guard
    body = _function(text, "Resolve-DefenseClawGuardianPublicationBeforeTransaction")
    assert body.index("Stop-DefenseClawService -Name $GuardianServiceName") < body.index("Start-DefenseClawService -Name $GuardianServiceName")
    assert "No transaction was opened and nothing was changed" in body
    # Only a running Guardian is restarted, and only when the records are not one publication.
    assert "-ne [ServiceProcess.ServiceControllerStatus]::Running" in body
    assert "Test-DefenseClawGuardianPublicationWhole" in body


def test_the_guardian_restart_never_leaves_the_guardian_stopped_and_looks_twice() -> None:
    """GAP-0994 delta-4 F1, F2: a start that fails after the stop is tried again with
    the start mode put back and then named; a look between the three writes is
    re-read before it can restart a healthy Guardian."""
    body = _function(_text(), "Resolve-DefenseClawGuardianPublicationBeforeTransaction")
    assert "GuardianRepublishRecheckSeconds" in body
    assert body.index("GuardianRepublishRecheckSeconds") < body.index("Stop-DefenseClawService -Name $GuardianServiceName")
    stop = body.index("Stop-DefenseClawService -Name $GuardianServiceName")
    assert body.rindex("try {", 0, stop) > body.index("Get-DefenseClawServiceStartMode")
    catch = body[body.index("catch {", stop) :]
    assert "Set-DefenseClawServiceStartMode -Name $GuardianServiceName -StartMode $startMode" in catch
    assert "Start-DefenseClawService -Name $GuardianServiceName" in catch and "could not be started" in catch


def test_the_rebuilt_record_must_name_the_programs_the_services_run() -> None:
    """GAP-0994 delta-4 F3: no vacuous pass of the rollback check, and the rebuild is
    refused before any swap when the record cannot name them."""
    text = _text()
    required = _function(text, "Get-DefenseClawRebuiltRecordRequiredArtifacts")
    for name in ("gateway", "hook", "sensor_helper"):
        assert f"'{name}'" in required
    check = _function(text, "Assert-DefenseClawRebuiltRecordArtifacts")
    assert "Get-DefenseClawRebuiltRecordRequiredArtifacts" in check and "names no digest" in check
    body = _function(text, "Invoke-DefenseClawStandaloneRecordRecovery")
    assert body.index("Assert-DefenseClawRebuiltRecordCoversArtifacts -Layout $Layout -Value $deploymentValue") < body.index(
        "Publish-DefenseClawRecordKeepingOld `\n"
    )
    unreadable = _function(text, "Repair-DefenseClawUnreadableDeploymentMetadata")
    assert unreadable.index("Assert-DefenseClawRebuiltRecordCoversArtifacts -Layout $Layout -Value $rebuilt") < unreadable.index(
        "Write-DefenseClawJsonAtomic -Path $Layout.MetadataPath"
    )
    refusal = _function(text, "Format-DefenseClawRebuiltRecordArtifactRefusal")
    assert "Nothing was changed and every service is as it was" in refusal and "/repair" in refusal


def test_a_whole_guardian_pass_that_failed_with_no_failed_target_is_published_again() -> None:
    """fc36 EW-02 (GAP-0602, GAP-0974, GAP-0994): the Guardian publishes ok=false with no
    failed target while it cannot read the deployment record; Setup restarts it after the
    record is repaired, and the next lifecycle reads no release from a rebuilt record."""
    text = _text()
    incomplete = _function(text, "Test-DefenseClawGuardianPublicationIncomplete")
    assert "PSObject.Properties['ok']" in incomplete and "PSObject.Properties['failure_count']" in incomplete
    body = _function(text, "Resolve-DefenseClawGuardianPublicationBeforeTransaction")
    stop = body.index("Stop-DefenseClawService -Name $GuardianServiceName")
    assert body.count("Test-DefenseClawGuardianPublicationCurrent -Layout $Layout", 0, stop) == 2
    wait = body[body.index("$deadline = "):]
    assert "Test-DefenseClawGuardianPublicationIncomplete" in wait and "No transaction was opened and nothing was changed" in wait
    lifecycle = _function(text, "Invoke-DefenseClawInstallLikeLifecycle")
    read = lifecycle.index("([string]$metadata.product_version) -match")
    assert lifecycle.rindex("$null -ne $metadata.PSObject.Properties['product_version'] -and", 0, read) > read - 120
