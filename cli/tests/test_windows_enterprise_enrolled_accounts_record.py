# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1800 (RV-1733c P3): the guardian's enrolled-accounts record is a lifecycle file.

hook-guardian-state\\enrolled-accounts.json (GAP-1733) is written by every
guardian pass that changes the set of enrolled accounts, with the same
writer, owner and access list as the protection ledger beside it. It was
outside the GAP-0977 hold list and Setup's access-list re-stamp, so an
administrator tool or anti-virus scan holding it stalled the guardian's
publish with nothing naming the file, and a drifted access list on it was
never re-stamped. It is now in the hold list (PowerShell and the CLI list)
and in the re-stamp of the authorization files.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
GO_HELD = ROOT / "internal" / "cli" / "windows_enterprise_guardian_state_held_windows.go"


def _function(text: str, name: str) -> str:
    start = text.index(f"function {name} {{")
    end = text.index("\nfunction ", start + 1)
    return text[start:end]


def test_the_hold_list_names_the_enrolled_accounts_record() -> None:
    files = _function(MODULE.read_text(encoding="utf-8"), "Get-DefenseClawGuardianStateFiles")
    assert "'protected_targets.json', 'activation.json', 'user-cleanup.json', 'enrolled-accounts.json'" in files
    go = GO_HELD.read_text(encoding="utf-8")
    assert ("[]string{managed.HookGuardianAuthorizationFile, hookGuardianActivationFile, "
            "managed.HookGuardianUserCleanupFile, managed.HookGuardianEnrolledAccountsFile}") in go


def test_setup_re_stamps_the_enrolled_accounts_record_like_the_ledger() -> None:
    acls = _function(MODULE.read_text(encoding="utf-8"), "Set-DefenseClawManagedAcls")
    loop = acls.index("foreach ($authorizationFile in @(")
    stamp = acls.index("-Kind AuthorizationFile", loop)
    block = acls[loop:stamp]
    assert "$Layout.AuthorizationLedgerPath" in block
    assert "'activation.json'" in block
    assert "'enrolled-accounts.json'" in block
