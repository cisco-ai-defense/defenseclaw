# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Exact-DACL regression contracts for Windows enterprise managed paths."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-exact-acl-smoke.ps1"


def _powershell_engines() -> list[str]:
    candidates: list[str | None] = [
        shutil.which("powershell.exe"),
        shutil.which("pwsh.exe"),
    ]
    windows_root = os.environ.get("SystemRoot")
    if windows_root:
        candidates.append(str(Path(windows_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"))

    engines: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.is_file():
            continue
        resolved = str(path.resolve())
        key = os.path.normcase(resolved)
        if key not in seen:
            seen.add(key)
            engines.append(resolved)
    return engines


def _powershell_engines_or_fail() -> list[str]:
    """Return the parametrize input; on Windows, refuse an empty list.

    An empty parametrize input silently emits zero test cases, so a Windows
    CI runner that could not locate any PowerShell engine would still report
    the whole suite as green. Fail-loud with a single parametrized case that
    pytest can report as an assertion failure instead.
    """
    engines = _powershell_engines()
    if engines:
        return engines
    if os.name == "nt":
        return ["<no-powershell-engine-found>"]
    return []


def _extract_function_body(source: str, function_name: str, terminator: str) -> str:
    """Return the slice of source between two anchors, or raise AssertionError.

    The DefenseClawEnterprise module has several similarly-shaped foreach
    loops. Using ``source.index("foreach ...")`` on the raw text picks the
    first match and scans to end-of-file, mixing in code from unrelated
    loops. Callers use this helper to bind an assertion to a specific
    function so a missing anchor produces a readable failure instead of a
    silent scope drift.
    """
    start = source.find(function_name)
    if start < 0:
        raise AssertionError(f"anchor not found: {function_name!r}")
    end = source.find(terminator, start + len(function_name))
    if end < 0:
        raise AssertionError(
            f"terminator {terminator!r} not found after {function_name!r}",
        )
    return source[start:end]


def test_canonical_setter_replaces_the_entire_protected_dacl() -> None:
    source = MODULE.read_text(encoding="utf-8")
    setter = source[
        source.index("function New-DefenseClawCanonicalPathAcl") : source.index(
            "function Set-DefenseClawBootstrapRootAcl"
        )
    ]

    assert "$security.SetAccessRuleProtection($true, $false)" in setter
    assert "[Security.AccessControl.DirectorySecurity]::new()" in setter
    assert "[Security.AccessControl.FileSecurity]::new()" in setter
    assert "$security.SetOwner($administrators)" in setter
    assert "$security.SetGroup($administrators)" in setter
    assert "Microsoft.PowerShell.Security\\Set-Acl" in setter
    assert "Assert-DefenseClawCanonicalPathAcl" in setter
    assert "does not have the exact canonical DACL" in setter
    assert "DiscretionaryAclAutoInherited" in setter
    assert "RawSecurityDescriptor" in setter
    assert "Test-DefenseClawExactRawDACL" in setter
    assert "GetFileSecurityDescriptor" in setter
    assert "GetSecurityInfo" in source
    assert "FILE_FLAG_OPEN_REPARSE_POINT" in source
    assert "DiscretionaryAcl.BinaryLength" not in setter
    assert "$actualDACL.BinaryLength" in setter
    assert "$actualDACL.GetBinaryForm" in setter
    assertion = setter[
        setter.index("function Assert-DefenseClawCanonicalRawPathAcl") : setter.index("function Set-DefenseClawPathAcl")
    ]
    assert "GetSecurityDescriptorSddlForm" not in assertion
    assert "GetFileSecurityDescriptor" in assertion
    assert "Test-DefenseClawExactRawDACL" in assertion
    assert "Get-Acl" not in assertion
    assert "$ownerSID -cne $expectedOwnerSID" in assertion
    assert "$groupSID -cne $expectedGroupSID" in assertion
    assert "Invoke-DefenseClawNative" not in setter
    assert "$script:IcaclsExe" not in setter


def test_state_root_ancestor_grant_is_additive_not_a_canonical_seizure() -> None:
    """A state-root ancestor is a shared vendor directory.

    ``C:\\ProgramData\\Cisco`` may belong to another Cisco product, so the
    gateway's traverse right is one added non-inherited ACE. The canonical
    protected DACL would take ownership and drop that product's ACEs.
    """
    source = MODULE.read_text(encoding="utf-8")
    grant = source[
        source.index("function Add-DefenseClawStateAncestorTraverseRule") : source.index(
            "function Assert-DefenseClawStateAncestorTraverse"
        )
    ]

    assert "PurgeAccessRules" in grant
    assert "InheritanceFlags]::None" in grant
    assert "Get-Acl" in grant
    # The canonical builder replaces the owner and the whole DACL.
    assert "New-DefenseClawCanonicalPathAcl" not in grant
    assert "Set-DefenseClawPathAcl" not in grant
    assert "SetAccessRuleProtection" not in grant
    assert "SetOwner" not in grant

    # Bind the ancestor-loop assertion to the enclosing Set-DefenseClawManagedAcls
    # function so the four similar `foreach ($ancestor in
    # @($Layout.StateRootAncestors))` blocks elsewhere in the module can't
    # cause source.index to select the wrong loop and scan the rest of the
    # file. `_extract_function_body` raises AssertionError if either anchor
    # goes missing so a rename shows up as a readable failure.
    applied = _extract_function_body(
        source,
        "function Set-DefenseClawManagedAcls",
        "function Set-DefenseClawManagedCoreAcls",
    )
    assert "foreach ($ancestor in @($Layout.StateRootAncestors)) {" in applied
    assert "Grant-DefenseClawStateAncestorTraverse" in applied

    # The ancestor trust invariant still has to hold.
    verifier = source[
        source.index("function Assert-DefenseClawStateAncestorTraverse") : source.index(
            "function Initialize-DefenseClawManagedRoot"
        )
    ]
    assert "Assert-DefenseClawTrustedAncestor" in verifier
    assert "must not " in verifier
    assert "cannot traverse an ancestor of " in verifier

    # The base is an OS directory and the root carries its own DACL, so neither
    # appears in the ancestor list.
    ancestors = source[
        source.index("function Get-DefenseClawManagedRootAncestors") : source.index(
            "$script:StateAncestorTraverseRights"
        )
    ]
    assert "$index -lt $components.Count - 1" in ancestors


def test_fixed_managed_ipc_path_is_provisioned_for_the_exact_gateway_sid() -> None:
    source = MODULE.read_text(encoding="utf-8")
    provisioner = _extract_function_body(
        source,
        "function Initialize-DefenseClawManagedIPCDirectory",
        "function Set-DefenseClawManagedAcls",
    )
    assert "'Cisco Secure Client'" in provisioner
    assert "'DefenseClaw'" in provisioner
    assert "'ipc'" in provisioner
    assert "Get-DefenseClawServiceSID" in provisioner
    assert "Assert-DefenseClawCanonicalVolumePath" in provisioner
    assert "Assert-DefenseClawNoReparsePath" in provisioner
    assert "New-DefenseClawProtectedDirectory" in provisioner
    assert "$script:AuthenticatedUsersSID" in provisioner
    assert "-Kind ManagedIPCDirectory" in provisioner

    transaction_services = _extract_function_body(
        source,
        "function Set-DefenseClawManagedServicesForTransaction",
        "function Get-DefenseClawLayout",
    )
    provision_at = transaction_services.index(
        "Initialize-DefenseClawManagedIPCDirectory",
    )
    acl_at = transaction_services.index("Set-DefenseClawManagedCoreAcls")
    assert provision_at < acl_at

    verifier = _extract_function_body(
        source,
        "function Assert-DefenseClawEnterpriseDeployment",
        "function Get-DefenseClawLifecycleStatus",
    )
    assert "-Path $Layout.ManagedIPCDirectory" in verifier
    assert "-Kind ManagedIPCDirectory" in verifier
    assert "$script:AuthenticatedUsersSID" in verifier


def test_retained_runtime_acl_adoption_precedes_gateway_startup() -> None:
    source = MODULE.read_text(encoding="utf-8")
    adoption = _extract_function_body(
        source,
        "function Set-DefenseClawRetainedRuntimeAcls",
        "function Set-DefenseClawManagedCoreAcls",
    )
    assert "Assert-DefenseClawDescendant" in adoption
    assert "Assert-DefenseClawNoReparsePath" in adoption
    assert "GetRegularFileLinkCountNoFollow" in adoption
    assert "GetFileIdentity" in adoption
    assert "-Kind RuntimeDirectory" in adoption
    assert "'RuntimeFile'" in adoption
    assert "-Kind ([string]$file.kind)" in adoption
    assert "'redaction-correlation.key'" in adoption
    assert "'RuntimeSecretFile'" in adoption
    assert "[uint32]32" in adoption
    assert "retained runtime file changed while its ACL was adopted" in adoption
    assert adoption.index("while ($pending.Count -gt 0)") < adoption.index(
        "foreach ($directory in $directories)",
    )

    transaction_services = _extract_function_body(
        source,
        "function Set-DefenseClawManagedServicesForTransaction",
        "function Get-DefenseClawLayout",
    )
    assert "-DeferAutomaticStart" in transaction_services
    assert "Set-DefenseClawRetainedRuntimeAcls" in transaction_services
    assert transaction_services.index("Set-DefenseClawManagedServices") < (
        transaction_services.index("Set-DefenseClawRetainedRuntimeAcls")
    )
    assert transaction_services.index("Set-DefenseClawRetainedRuntimeAcls") < (
        transaction_services.index("Set-DefenseClawManagedCoreAcls")
    )


def test_redaction_key_transaction_is_metadata_only_and_restored_before_start() -> None:
    source = MODULE.read_text(encoding="utf-8")
    capture = _extract_function_body(
        source,
        "function Get-DefenseClawRedactionKeySecuritySnapshot",
        "function Restore-DefenseClawRedactionKeySecuritySnapshot",
    )
    restore_metadata = _extract_function_body(
        source,
        "function Restore-DefenseClawRedactionKeySecuritySnapshot",
        "function Set-DefenseClawManagedCoreAcls",
    )

    for body in (capture, restore_metadata):
        assert "redaction-correlation.key" in body or ("$Layout.RedactionCorrelationKeyPath" in body)
        assert "[uint32]32" in body
        assert "Get-Content" not in body
        assert "ReadAllBytes" not in body
        assert "ReadAllText" not in body
        assert "Copy-Item" not in body
        assert "Get-FileHash" not in body

    assert "GetRegularFileSecuritySnapshotNoFollow" in capture
    assert "file_identity" in capture
    assert "security_descriptor" in capture
    assert "SetRegularFileSecurityDescriptorNoFollow" in restore_metadata
    assert "[string]$recorded.file_identity" in restore_metadata

    transaction = _extract_function_body(
        source,
        "function New-DefenseClawTransaction",
        "function Set-DefenseClawTransactionManagedHooksTeardownPrepared",
    )
    capture_at = transaction.index(
        "Get-DefenseClawRedactionKeySecuritySnapshot",
    )
    last_initial_stop_at = transaction.index(
        "Stop-DefenseClawService -Name $brokerServiceName",
    )
    first_generic_copy_at = transaction.index(
        "Microsoft.PowerShell.Management\\Copy-Item",
    )
    assert last_initial_stop_at < capture_at < first_generic_copy_at
    assert transaction.index("redaction_key_security = $redactionKeySecurity") < (
        transaction.index("Write-DefenseClawJsonAtomic -Value $snapshot")
    )
    destinations = transaction[
        transaction.index("$destinations =") : transaction.index(
            "$index = 0",
            transaction.index("$destinations ="),
        )
    ]
    assert "RedactionCorrelationKeyPath" not in destinations

    restore = _extract_function_body(
        source,
        "function Restore-DefenseClawTransaction {",
        "function Assert-DefenseClawRestoredTransactionReadyForActivation",
    )
    prior_services_at = restore.index("$previousServices =")
    recreate_at = restore.index(
        "Set-DefenseClawManagedServices `",
        prior_services_at,
    )
    restore_key_at = restore.index(
        "Restore-DefenseClawRedactionKeySecuritySnapshot",
    )
    remove_created_service_at = restore.index(
        "Remove-DefenseClawService -Name ([string]$service.name)",
    )
    readiness_at = restore.index(
        "Assert-DefenseClawRestoredTransactionReadyForActivation",
    )
    assert recreate_at < restore_key_at < remove_created_service_at < readiness_at


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell smoke")
@pytest.mark.parametrize("engine", _powershell_engines_or_fail())
def test_every_managed_path_kind_has_an_exact_descriptor(engine: str) -> None:
    # Guard against a Windows runner that ships without any PowerShell
    # engine. `_powershell_engines()` returned []; the parametrize decorator
    # would otherwise emit zero test cases and let the exact-DACL contract
    # go unverified on the ONLY platform where it can be verified. The
    # sentinel value is placed there by _powershell_engines_or_fail().
    if engine == "<no-powershell-engine-found>":
        pytest.fail(
            "No powershell.exe or pwsh.exe was found on this Windows runner; "
            "the exact-DACL smoke cannot run and must not silently pass.",
        )
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            os.fspath(SMOKE),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    payload = json.loads(completed.stdout)
    assert payload == {
        "ok": True,
        "schema_version": 1,
        "descriptors_checked": 18,
        "stale_explicit_aces_retained": False,
        "object_type_mismatches_rejected": True,
        "auto_inherited_control_flag_accepted": True,
        "ace_mismatches_rejected": True,
        "native_raw_acl_query_checked": True,
        "split_explicit_aces_rejected": True,
        "installer_verifier_pairings_checked": 18,
        "acl_kind_sets_agree": True,
        "state_ancestor_grant_is_additive": True,
        "retained_runtime_tree_adopted": True,
        "retained_runtime_hard_links_rejected": True,
        "retained_runtime_secret_acl_exact": True,
        "retained_runtime_secret_bytes_preserved": True,
        "retained_runtime_secret_hash_preserved": True,
        "retained_runtime_secret_identity_preserved": True,
    }
