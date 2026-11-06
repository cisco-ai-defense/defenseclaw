# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the lifecycle pins of an interrupted standalone transaction.

An Upgrade cut off mid-copy leaves two releases on disk (rel-1-0-6
GAP-0649). The fix keeps one release's toolchain per lifecycle run; these
checks pin where each piece runs (g649 review F2):

- the transaction pins are written inside the rollback scope and before the
  first payload copy, which follows the staging order;
- both pending-recovery sites stop a Repair that restored another release
  only after the recovery's activation check;
- the module re-admits the pinned pair only for a hash-pinned record;
- the installed CLI's bootstrap reads the transaction pins only for a
  trusted hash-pinned standalone record (g649 review F1).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"


def _function(text: str, name: str) -> str:
    match = re.search(rf"^function {re.escape(name)} \{{\n", text, re.MULTILINE)
    assert match, f"{name} not found"
    end = text.find("\n}\n", match.end())
    assert end > 0, f"{name} has no end"
    return text[match.start() : end + 3]


def _code(body: str) -> str:
    """The body without its comment-based help and line comments."""
    body = re.sub(r"<#.*?#>", "", body, flags=re.DOTALL)
    return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))


def test_pins_are_written_in_the_rollback_scope_before_the_first_copy() -> None:
    body = _code(_function(MODULE.read_text(encoding="utf-8"), "Invoke-DefenseClawInstallLikeLifecycle"))
    snapshot = body.index("$snapshot = New-DefenseClawTransaction")
    rollback_try = body.index("$committedLifecycleRecovery = $null\n    try {", snapshot)
    pins = body.index("Write-DefenseClawTransactionLifecyclePins", snapshot)
    copy_loop = body.index("foreach ($name in @(Get-DefenseClawStagingOrder -Names @($Sources.Keys)", snapshot)
    first_copy = body.index("Install-DefenseClawSourceDescriptor", copy_loop)
    assert body.count("Write-DefenseClawTransactionLifecyclePins") == 1
    assert rollback_try < pins < copy_loop < first_copy
    # The first statement inside the try.
    assert body[rollback_try:pins].rstrip().endswith("try {")


def test_both_recovery_sites_stop_after_the_activation_check() -> None:
    text = MODULE.read_text(encoding="utf-8")
    code = _code(text)
    calls = [m.start() for m in re.finditer(r"Test-DefenseClawRecoveryRestoredOtherRelease `\n", code)]
    assert len(calls) == 2
    for call in calls:
        recover = code.rfind("Recover-DefenseClawPendingTransaction `", 0, call)
        activation = code.rfind("Assert-DefenseClawRecoveryActivatedForAction `", 0, call)
        assert recover >= 0 and activation > recover
        # Nothing runs the restored payload between the activation check and the stop.
        between = code[activation:call]
        assert "Invoke-" not in between and "Install-" not in between
        # The stop returns the restored deployment's status.
        after = code[call : call + 700]
        assert "Get-DefenseClawRecoveryRestoredOtherReleaseResult" in after
        assert "-Action $Action" in after[after.index("Get-DefenseClawRecoveryRestoredOtherReleaseResult") :]
    # An installed-CLI Uninstall stops there too and fails with the next step
    # instead of removing a restored release with this module (g649 review F4).
    stop = _code(_function(text, "Test-DefenseClawRecoveryRestoredOtherRelease"))
    assert "$Action -notin @('Repair', 'Uninstall')" in stop
    assert "$Sources.ContainsKey('gateway')" in stop
    result = _code(_function(text, "Get-DefenseClawRecoveryRestoredOtherReleaseResult"))
    uninstall = result.index("if ($Action -eq 'Uninstall') {")
    assert uninstall < result.index("throw", uninstall) < result.index("Get-DefenseClawLifecycleStatus")
    assert "nothing was removed. Run the same uninstall again" in result


def test_module_readmits_the_pinned_pair_only_for_a_hash_pinned_record() -> None:
    body = _code(_function(MODULE.read_text(encoding="utf-8"), "Initialize-DefenseClawRecordedPayloadTrust"))
    gate = body.index("-cne 'hash_pinned'")
    reader = body.index("Get-DefenseClawPendingTransactionLifecyclePins")
    assert gate < body.index("return", gate) < reader


def test_bootstrap_reads_transaction_pins_only_for_a_hash_pinned_record() -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    recorded = _code(_function(text, "Get-DefenseClawBootstrapRecordedModulePin"))
    reset = recorded.index("$script:DefenseClawBootstrapRecordedHashPinned = $false")
    gate = recorded.index("-cne 'hash_pinned'")
    flag = recorded.index("$script:DefenseClawBootstrapRecordedHashPinned = $true")
    installer_check = recorded.index("$running = (")
    assert reset < recorded.index("try {") < gate < flag < installer_check

    select = _code(_function(text, "Get-DefenseClawBootstrapInstalledModulePin"))
    recorded_call = select.index("Get-DefenseClawBootstrapRecordedModulePin")
    flag_check = select.index("if (-not [bool]$script:DefenseClawBootstrapRecordedHashPinned) {")
    transaction_call = select.index("Get-DefenseClawBootstrapTransactionModulePin")
    assert recorded_call < flag_check < transaction_call
    assert select[flag_check : transaction_call].count("return $recorded") == 1

    # The installed-CLI branch is the only caller, and nothing else reads the
    # transaction pins.
    code = _code(text)
    assert code.count("Get-DefenseClawBootstrapInstalledModulePin `") == 1
    assert code.count("Get-DefenseClawBootstrapTransactionModulePin `") == 1
    branch = code.index("Get-DefenseClawBootstrapInstalledModulePin `")
    assert "$TrustMode -ceq 'Authenticode'" in code[branch - 600 : branch]
