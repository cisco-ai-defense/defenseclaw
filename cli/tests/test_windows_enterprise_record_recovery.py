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
    assert "-RebuildBecause" in body


def test_the_rebuild_is_checked_before_anything_is_moved() -> None:
    body = _function(_text(), "Invoke-DefenseClawStandaloneRecordRecovery")
    ready = body.index("Assert-DefenseClawMetadataRebuildReady")
    move = body.index("= Move-DefenseClawStandaloneRecordAside")
    rebuild = body.index("[void](Repair-DefenseClawUnreadableDeploymentMetadata")
    assert ready < move < rebuild
    # A failed rebuild puts every record back; the kept file is stamped only
    # after the record was written again, so moving it back restores the host.
    assert body.index("Move-Item", rebuild) > rebuild and "back where it was" in body
    assert body.index("Protect-DefenseClawKeptRecord", rebuild) > rebuild
    aside = _function(_text(), "Move-DefenseClawStandaloneRecordAside")
    assert "Set-DefenseClawPathAcl" not in aside
    repair = _function(_text(), "Repair-DefenseClawUnreadableDeploymentMetadata")
    assert "Assert-DefenseClawMetadataRebuildReady" in repair
    ready_body = _function(_text(), "Assert-DefenseClawMetadataRebuildReady")
    assert "Write-DefenseClawJsonAtomic" not in ready_body and "Move-Item" not in ready_body


def test_an_uninstall_refusal_names_the_forced_way_out() -> None:
    gate = _function(_text(), "Assert-DefenseClawStandaloneContentTrusted")
    tail = gate[gate.rindex("throw $message") - 600 : gate.rindex("throw $message")]
    assert "$Scope -cne 'Lifecycle'" in tail and "/uninstall FORCE=1 PURGE=1" in tail


def test_move_aside_renames_the_object_and_refuses_a_changeable_folder() -> None:
    body = _function(_text(), "Move-DefenseClawStandaloneRecordAside")
    folder = body.index("Get-DefenseClawPathAclVerdicts")
    move = body.index("Move-Item")
    assert folder < move
    assert ".rejected-" in body
    # The live path is free once the object is renamed.
    assert "Set-DefenseClawPathAcl" not in body


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
    assert go.rindex("noteWindowsEnterpriseEnsureDriftRepairs(result, driftRepaired)", 0, call) > go.rindex("func runWindowsEnterpriseStandaloneEnsureOnce(", 0, call)
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
