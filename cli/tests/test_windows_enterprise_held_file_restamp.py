# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0763: an in-place re-stamp of a recorded file holds the file first.

On the standalone profile every in-place re-stamp of a regular file is one
transaction: the file is held with a handle no other program can write or
delete under, links are checked on it, and only then is anything written. A
holder stops the stamp before the first write. These checks pin the order
and the gates in the module (the native smoke runs the behavior).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-standalone-held-file-restamp-smoke.ps1"


def _text() -> str:
    return MODULE.read_text(encoding="utf-8-sig")


def _function(text: str, name: str) -> str:
    match = re.search(r"^function " + re.escape(name) + r" \{\n(.*?)^\}\n", text, re.S | re.M)
    assert match, f"{name} not found"
    return match.group(1)


def test_set_path_acl_holds_a_standalone_file_before_it_stamps() -> None:
    body = _function(_text(), "Set-DefenseClawPathAcl")
    hold = body.index("Open-DefenseClawRestampHold")
    stamp = body.index("Invoke-DefenseClawPathAclStamp")
    release = body.index("Close-DefenseClawRestampHold")
    assert hold < stamp < release
    gate = body[:hold]
    assert "Test-DefenseClawStandaloneProfile" in gate
    assert "'InstallFile', 'ServiceInstallFile'" in gate
    assert "-notlike '*Directory'" in gate
    # The stamp runs under try and the hold is released in finally.
    assert re.search(r"try \{\s*Invoke-DefenseClawPathAclStamp.*?finally \{\s*Close-DefenseClawRestampHold", body, re.S)


def test_the_stamp_function_is_the_old_body_not_a_second_writer() -> None:
    text = _text()
    body = _function(text, "Invoke-DefenseClawPathAclStamp")
    assert "Assert-DefenseClawNoReparsePath" in body
    assert "Open-DefenseClawRestampHold" not in body
    # Nothing but the wrapper calls it.
    assert len(re.findall(r"Invoke-DefenseClawPathAclStamp\b", text)) == 2


def test_the_native_gate_follows_the_standalone_profile_at_every_use() -> None:
    text = _text()
    # Both returns of Initialize-DefenseClawNativeSecurity (the cached type and
    # the freshly compiled one) set the gate; the C# here-string inside the
    # function keeps the regex above from spanning it.
    start = text.index("function Initialize-DefenseClawNativeSecurity {")
    end = text.index("function Assert-DefenseClawAdministrator {")
    assert text[start:end].count("RefuseHeldRestamp = [bool](Test-DefenseClawStandaloneProfile)") == 2


def test_the_native_open_holds_read_only_and_only_on_standalone() -> None:
    text = _text()
    start = text.index("private static IntPtr OpenFileForRestamp(")
    body = text[start : text.index("public static IntPtr HoldRegularFileForRestampNoFollow", start)]
    assert "if (!RefuseHeldRestamp || directory)" in body
    assert "desiredAccess | FILE_READ_DATA" in body
    assert "FILE_SHARE_READ," in body
    assert "FILE_SHARE_WRITE" not in body and "FILE_SHARE_DELETE" not in body
    # The two native cores open through it, and the uninstall's authority
    # repair (backup intent) keeps its open.
    assert text.count("OpenFileForRestamp(") >= 5
    assert "backupIntent,\n                    !backupIntent);" in text


def test_a_hold_refusal_is_never_swallowed_by_the_self_heal_or_the_retry() -> None:
    text = _text()
    assert "Get-DefenseClawHeldFileRefusal -ErrorRecord $_" in _function(text, "Assert-DefenseClawPathAcl")
    assert "Get-DefenseClawHeldFileRefusal -ErrorRecord $_" in _function(text, "Set-DefenseClawSharedPathAcl")


@pytest.mark.parametrize(
    "function",
    [
        "Restore-DefenseClawStandaloneCodexRequirementsAcl",
        "Complete-DefenseClawCodexRequirementsRemoval",
        "Set-DefenseClawStandaloneSecretSddl",
    ],
)
def test_every_path_based_restamp_of_a_recorded_file_holds_it_first(function: str) -> None:
    body = _function(_text(), function)
    hold = body.index("Open-DefenseClawRestampHold")
    for write in ("Set-Acl", "Set-DefenseClawPathAcl"):
        for match in re.finditer(re.escape(write), body):
            assert match.start() > hold, f"{function}: {write} before the hold"
    if "Get-FileHash" in body:
        assert body.index("Get-FileHash") > hold


def test_the_transaction_rollback_holds_the_file_before_restoring_its_recorded_acl() -> None:
    text = _text()
    # A shared Codex file waits at most 30 seconds for a late holder and then
    # ends with the retryable held code (GAP-0803); every other file is held
    # at once, as before.
    start = text.index("$restoreHold = if ($isSharedCodexFile -and (Test-DefenseClawStandaloneProfile)) {")
    block = text[start : start + 2500]
    assert "Open-DefenseClawCodexRollbackHold -Layout $Layout -Path $destination" in block[:300]
    assert "Open-DefenseClawRestampHold -Path $destination" in block[:400]
    assert block.index("Set-Acl") > 0
    assert "Close-DefenseClawRestampHold -Handle $restoreHold" in text[start : start + 4000]


def test_the_smoke_covers_each_holder_the_link_and_the_secure_client_twin() -> None:
    smoke = SMOKE.read_text(encoding="utf-8-sig")
    for needle in (
        "a DELETE handle without delete sharing",
        "a write handle",
        "a read handle that does not share read",
        "CreateHardLinkW",
        "Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient",
        "(Get-Sddl $Path) -ne $before",
    ):
        assert needle in smoke
