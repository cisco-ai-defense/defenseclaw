# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""p0-round:GAP-1365, GAP-1585: the first forced uninstall after a killed first install.

A first install killed before it wrote deployment.json leaves StateRoot with a
pending transaction and no record. The uninstall read that as untrusted
deployment evidence and took the metadata-free purge, which refuses to bypass
the transaction: the first Setup /uninstall FORCE=1 ended 1603 and only a
retry finished. Now a forced uninstall goes on as the forced uninstall only
when the record is missing from an existing admin-only StateRoot (the
$uninstallMetadataMissing flag, set only there). A present record that fails
its owner, ACL, reparse, link or content check keeps the metadata-free purge
with FORCE as without (GAP-1585), and nothing changes without FORCE. The
forced uninstall also refuses a same-named service it does not own instead of
an advisory; Secure Client never passes that switch.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"

MISSING = "deployment.json is missing from an existing StateRoot"

# The (reason, missing flag) pair the lifecycle derives for each state of the
# record, from the uninstall ACL recovery and the StateRoot probe.
SCENARIOS = {
    # StateRoot exists, admin-only, no deployment.json (killed first install).
    "record-missing": (MISSING, True),
    # StateRoot writable by someone else, record missing: not trusted to route.
    "record-missing-weak-stateroot": (MISSING, False),
    # A present record whose owner, ACL, reparse point or link count fails:
    # Repair-DefenseClawUninstallAdminFileAcl throws, its message is the reason.
    "repair-throws": ("refusing uninstall ACL recovery: foreign owner on deployment.json", False),
    # The record passes the ACL check but its content fails the Required read.
    "bad-content": ("deployment metadata is not valid JSON", False),
    # A trusted record, and no StateRoot at all: no reason.
    "trusted": ("", False),
    "no-stateroot": ("", False),
}
# Expected route per scenario: (with FORCE, without FORCE); True = metadata-free purge.
EXPECTED = {
    "record-missing": (False, True),
    "record-missing-weak-stateroot": (True, True),
    "repair-throws": (True, True),
    "bad-content": (True, True),
    "trusted": (False, False),
    "no-stateroot": (False, False),
}


def _module() -> str:
    return MODULE.read_text(encoding="utf-8")


def _function(text: str, name: str) -> str:
    start = text.index(f"function {name} {{")
    end = text.index("\nfunction ", start + 1)
    return text[start:end]


def test_the_missing_record_flag_is_set_only_beside_the_missing_record_reason() -> None:
    text = _module()
    sets_true = [m.start() for m in re.finditer(r"\$uninstallMetadataMissing = Test-DefenseClawForcedUninstallStateRootAdminOnly", text)]
    assert len(sets_true) == 1
    resets = [m.start() for m in re.finditer(r"\$uninstallMetadataMissing = \$false", text)]
    assert len(resets) == 1
    # It is set inside the branch that names the missing record, right after it.
    branch = text.rindex("if ($null -ne $stateRootBefore) {", 0, sets_true[0])
    reason = text.index(f"'{MISSING}'", branch)
    assert branch < reason < sets_true[0] < branch + 600
    # And never anywhere else (the Repair catch only sets the reason).
    assert len(re.findall(r"\$uninstallMetadataMissing\s*=", text)) == 2


def test_the_route_keys_on_force_and_the_missing_record_flag() -> None:
    text = _module()
    call = text.index("if (Test-DefenseClawUninstallUsesUntrustedMetadataPurge `")
    following = text[call : call + 600]
    assert "-MetadataMissing $uninstallMetadataMissing" in following
    assert "-MetadataExists" not in following
    assert "-Force:$Force" in following
    assert "return Invoke-DefenseClawUntrustedMetadataRecoveryPurge" in following
    assert text.index("return Invoke-DefenseClawForcedUninstall `", call) > call
    decision = _function(text, "Test-DefenseClawUninstallUsesUntrustedMetadataPurge")
    assert "if ($Force -and $MetadataMissing) {" in decision
    assert "MetadataExists" not in decision


def test_the_pre_check_shares_the_repair_ancestor_rule_and_a_no_follow_probe() -> None:
    text = _module()
    helper = _function(text, "Assert-DefenseClawStateRootAncestorsAdminOnly")
    assert "@($Layout.StateRootAncestors)" in helper
    repair = _function(text, "Repair-DefenseClawUninstallAdminFileAcl")
    assert "Assert-DefenseClawStateRootAncestorsAdminOnly -Layout $Layout" in repair
    assert "foreach ($ancestor in" not in repair
    precheck = _function(text, "Test-DefenseClawForcedUninstallStateRootAdminOnly")
    assert "Assert-DefenseClawStateRootAncestorsAdminOnly -Layout $Layout" in precheck
    assert "GetDirectorySecuritySnapshotNoFollowIfExists($candidate)" in precheck
    assert "Management\\Test-Path" not in precheck


def test_the_forced_uninstall_checks_service_ownership_strictly() -> None:
    text = _module()
    preparation = _function(text, "Invoke-DefenseClawForcedUninstallPreparation")
    assert preparation.count("Assert-DefenseClawOwnedServiceOrAbsent `\n        -Strict `") == 4
    owned = _function(text, "Assert-DefenseClawOwnedServiceOrAbsent")
    assert owned.count("if ($Strict -or (Test-DefenseClawTrustStrictAncestors)) {") == 2
    # Nothing else passes -Strict: every other caller (Secure Client included)
    # keeps the advisory.
    assert len(re.findall(r"Assert-DefenseClawOwnedServiceOrAbsent `\n\s+-Strict", text)) == 4


HARNESS = r"""
param([string]$ModulePath, [string]$Work)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Import-Module $ModulePath -PassThru -Force -DisableNameChecking
$rows = @(
__ROWS__
)
foreach ($row in $rows) {
    foreach ($force in @($true, $false)) {
        $got = & $module { param($r, $m, $f) Test-DefenseClawUninstallUsesUntrustedMetadataPurge -Reason $r -MetadataMissing $m -Force:$f } $row[1] $row[2] $force
        "route $($row[0]) force=$force purge=$got"
    }
}
# The metadata-free purge refuses a pending transaction (untrusted, no FORCE).
$refusal = & $module {
    function Get-DefenseClawUnfinishedLifecycleEvidence { param($Layout) 'pending transaction' }
    try {
        Invoke-DefenseClawUntrustedMetadataRecoveryPurge -Layout @{} -Sources @{} -GatewayServiceName g -GuardianServiceName h -Reason 'deployment.json is missing from an existing StateRoot'
        'no refusal'
    } catch { $_.Exception.Message }
}
"pending refusal: $refusal"
# The StateRoot pre-check on real folders: an admin-only vendor ancestor
# holding an admin-only StateRoot passes; a Users-writable install folder, a
# Users-writable ancestor (p0-round:GAP-1586) or a junction fails.
$vendor = Join-Path $Work 'Cisco'; $state = Join-Path $vendor 'DefenseClaw'; $install = Join-Path $state 'install'
New-Item -ItemType Directory -Force $install | Out-Null
icacls $vendor /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
icacls $vendor /setowner '*S-1-5-32-544' /T /Q | Out-Null
$layout = @{ StateRoot = $state; InstallStateDirectory = $install; StateRootAncestors = @($vendor) }
"precheck admin-only: " + (& $module { param($l) Test-DefenseClawForcedUninstallStateRootAdminOnly -Layout $l } $layout)
icacls $vendor /grant '*S-1-5-32-545:(M)' /Q | Out-Null
"precheck users-modify ancestor: " + (& $module { param($l) Test-DefenseClawForcedUninstallStateRootAdminOnly -Layout $l } $layout)
icacls $vendor /remove:g '*S-1-5-32-545' /Q | Out-Null
"precheck admin-only again: " + (& $module { param($l) Test-DefenseClawForcedUninstallStateRootAdminOnly -Layout $l } $layout)
icacls $install /grant '*S-1-5-32-545:(OI)(CI)M' /Q | Out-Null
"precheck users-modify install: " + (& $module { param($l) Test-DefenseClawForcedUninstallStateRootAdminOnly -Layout $l } $layout)
$target = Join-Path $Work 'Target'; New-Item -ItemType Directory -Force $target | Out-Null
$link = Join-Path $vendor 'LinkRoot'; cmd /c mklink /J $link $target | Out-Null
"precheck junction: " + (& $module { param($l) Test-DefenseClawForcedUninstallStateRootAdminOnly -Layout $l } @{ StateRoot = $link; InstallStateDirectory = (Join-Path $link 'install'); StateRootAncestors = @($vendor) })
cmd /c rmdir $link | Out-Null
"__END__"
"""


def harness_text() -> str:
    rows = ",\n".join(
        "    @('{0}', '{1}', ${2})".format(name, reason.replace("'", "''"), "true" if missing else "false")
        for name, (reason, missing) in SCENARIOS.items()
    )
    return HARNESS.replace("__ROWS__", rows)


def check_harness_output(output: str) -> None:
    for name, (with_force, without_force) in EXPECTED.items():
        assert f"route {name} force=True purge={with_force}" in output, (name, output)
        assert f"route {name} force=False purge={without_force}" in output, (name, output)
    assert "pending refusal: untrusted deployment evidence requires authenticated recovery of the existing pending transaction" in output
    assert "precheck admin-only: True" in output
    assert "precheck users-modify ancestor: False" in output
    assert "precheck admin-only again: True" in output
    assert "precheck users-modify install: False" in output
    assert "precheck junction: False" in output


@pytest.mark.skipif(shutil.which("pwsh") is None or shutil.which("icacls") is None,
                    reason="needs Windows PowerShell 7 and icacls")
def test_the_lifecycle_inputs_route_as_expected(tmp_path: Path) -> None:
    harness = tmp_path / "harness.ps1"
    harness.write_text(harness_text(), encoding="utf-8")
    result = subprocess.run(
        [shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Work", str(tmp_path / "work")],
        capture_output=True, text=True, timeout=300, check=False,
    )
    assert result.returncode == 0, result.stderr
    check_harness_output(result.stdout)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == "--write-harness":
        Path(sys.argv[2]).write_text(harness_text(), encoding="utf-8")
    elif len(sys.argv) > 2 and sys.argv[1] == "--check":
        check_harness_output(Path(sys.argv[2]).read_text(encoding="utf-8-sig", errors="replace"))
        print("harness output OK")
