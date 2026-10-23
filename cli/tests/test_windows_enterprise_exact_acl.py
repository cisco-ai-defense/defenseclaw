# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Exact-DACL regression contracts for Windows enterprise managed paths."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-exact-acl-smoke.ps1"
WINDOWS_BUNDLE = ROOT / "internal" / "cli" / "windows_enterprise_bundle.go"
WINDOWS_BUNDLE_ACL = ROOT / "internal" / "cli" / "windows_enterprise_bundle_acl.go"
GO_STORE = ROOT / "internal" / "enterprisebundle" / "store.go"


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
    assert "SetDirectoryDaclNoFollow" in setter
    assert "PROTECTED_DACL_SECURITY_INFORMATION" in source
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
    # Get-Acl stays out of the verifier (it strips SE_DACL_PROTECTED on some
    # .NET revisions, which is the very bug the verifier is designed to
    # catch). The icacls /inheritance:r self-heal uses the native
    # GetFileSecurityDescriptor to re-read after forcing the protected flag.
    assert "Get-Acl" not in assertion
    assert "$ownerSID -cne $expectedOwnerSID" in assertion
    assert "$groupSID -cne $expectedGroupSID" in assertion
    assert "Invoke-DefenseClawNative" not in setter
    # icacls is permitted ONLY inside Assert-DefenseClawCanonicalRawPathAcl's
    # one-shot self-heal (restores PROTECTED_DACL_SECURITY_INFORMATION that
    # Set-Acl occasionally drops silently on Windows 10/11). It must not
    # appear anywhere else in the canonical setter: the setter still writes
    # bytes via Set-Acl and verifies via native GetFileSecurityDescriptor.
    raw_verifier = setter[
        setter.index("function Assert-DefenseClawCanonicalRawPathAcl") : setter.index(
            "function Test-DefenseClawCanonicalRawPathAcl"
        )
    ]
    assert "$script:IcaclsExe" in raw_verifier
    setter_without_raw_verifier = setter.replace(raw_verifier, "")
    assert "$script:IcaclsExe" not in setter_without_raw_verifier


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
    # The expected directory is the active profile's ManagedIPCDirectory:
    # Program Files\Cisco\Cisco Secure Client\DefenseClaw\ipc for Secure
    # Client (the AVC GUI contract), Program Files\Cisco\DefenseClaw\ipc for
    # standalone.
    assert "(Get-DefenseClawProfileRoots).ManagedIPCDirectory" in provisioner
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


def test_public_bundle_receipt_acl_does_not_expose_private_paths() -> None:
    source = MODULE.read_text(encoding="utf-8")
    builder = _extract_function_body(
        source,
        "function New-DefenseClawCanonicalPathAcl",
        "function Test-DefenseClawExactRawDACL",
    )
    cases = {
        kind: builder.split(f"        '{kind}' {{", 1)[1].split("\n        }", 1)[0]
        for kind in (
            "StateDirectory",
            "ConfigDirectory",
            "BundleDirectory",
            "BundleReceipt",
            "BundleVersionDirectory",
            "BundleVersionFile",
            "ConfigFile",
        )
    }
    for kind in (
        "StateDirectory",
        "ConfigDirectory",
        "BundleVersionDirectory",
        "BundleVersionFile",
        "ConfigFile",
    ):
        assert "$script:UsersSID" not in cases[kind], kind
    assert "        'AdminDirectory' {" not in builder
    assert "        'AdminFile' {" not in builder
    assert (
        "sid = $script:UsersSID\n"
        "                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute"
    ) in cases["BundleDirectory"]
    assert (
        "sid = $script:UsersSID\n"
        "                rights = [Security.AccessControl.FileSystemRights]::Read"
    ) in cases["BundleReceipt"]
    assert "$Kind -eq 'BundleDirectory'" in builder
    assert "-not $usersTraverseOnly" in builder

    contract = _extract_function_body(
        source,
        "function Invoke-DefenseClawBundleAclContract",
        "function Set-DefenseClawManagedAcls",
    )
    assert (
        "$bundleDirectory = Microsoft.PowerShell.Management\\Join-Path "
        "$Layout.ConfigDirectory 'bundles'"
    ) in contract
    classifier = _extract_function_body(
        source,
        "function Get-DefenseClawBundlePathKind",
        "function Invoke-DefenseClawBundleAclContract",
    )
    assert "$RelativePath -ceq 'receipt.json' -and -not $IsDirectory" in classifier
    assert "$top -ceq 'receipt-events'" in classifier
    assert "return 'BundleDirectory'" in classifier
    assert "^receipt-events\\\\[br]-[0-7][0-9A-HJKMNP-TV-Z]{25}\\.json$" in classifier
    # Change events are readable by the gateway service, not by standard users.
    assert "$top -ceq 'change-events'" in classifier
    assert "^change-events\\\\c-[0-7][0-9A-HJKMNP-TV-Z]{25}\\.json$" in classifier
    # So are the reservations of changes in progress (change-events\reserved).
    assert "$RelativePath -ceq 'change-events\\reserved' -and $IsDirectory" in classifier
    assert "^change-events\\\\reserved\\\\c-[0-7][0-9A-HJKMNP-TV-Z]{25}\\.json$" in classifier
    assert classifier.index("$top -ceq 'change-events'") < classifier.index("if ($IsDirectory) { return 'AdminDirectory' }")
    assert classifier.index("$top -ceq 'receipt-events'") < classifier.index("if ($IsDirectory) { return 'AdminDirectory' }")
    assert "if ($IsDirectory) { return 'AdminDirectory' }" in classifier
    assert "Get-DefenseClawBundlePathKind -RelativePath $relative" in contract
    assert "'BundleVersionDirectory'" in contract
    assert "'BundleVersionFile'" in classifier
    assert "'bundle-state.json'" in contract
    assert "'receipts'" in contract
    assert "Assert-DefenseClawCanonicalPathAcl -Path $item.Path -Expected $expected" in contract
    go = WINDOWS_BUNDLE.read_text(encoding="utf-8")
    store = GO_STORE.read_text(encoding="utf-8")
    assert "store.EnsurePublicReceiptEventsDirectory = ensureWindowsBundlePublicReceiptEventsDirectory" in go
    assert "return createWindowsBundleDirectory(path, windowsBundleDirectorySDDL(service.String()))" in go
    assert "ensureErr = s.EnsurePublicReceiptEventsDirectory(eventsDir)" in store
    assert "ensureErr = os.MkdirAll(eventsDir, 0o755)" in store
    assert "Set-DefenseClawPathAcl -Path $item.Path -Kind $item.Kind" in contract

    provisioner = _extract_function_body(
        source,
        "function Set-DefenseClawManagedAcls",
        "function Get-DefenseClawLayout",
    )
    assert (
        "Invoke-DefenseClawBundleAclContract -Layout $Layout "
        "-GatewayServiceSID $gatewaySID -Repair"
    ) in provisioner
    verifier = _extract_function_body(
        source,
        "function Assert-DefenseClawEnterpriseDeployment",
        "function Get-DefenseClawLifecycleStatus",
    )
    assert (
        "Invoke-DefenseClawBundleAclContract -Layout $Layout "
        "-GatewayServiceSID $gatewaySID"
    ) in verifier


def test_receipt_version_name_selects_creator_acl_on_every_asset() -> None:
    """Cross-check Go naming and SDDL with the PowerShell verifier contract."""
    module = MODULE.read_text(encoding="utf-8")
    smoke = SMOKE.read_text(encoding="utf-8")
    go = WINDOWS_BUNDLE.read_text(encoding="utf-8")
    go_acl = WINDOWS_BUNDLE_ACL.read_text(encoding="utf-8")
    store = GO_STORE.read_text(encoding="utf-8")
    classifier = _extract_function_body(
        module,
        "function Get-DefenseClawBundlePathKind",
        "function Invoke-DefenseClawBundleAclContract",
    )
    ps_pattern = re.search(r"\$top -cmatch '([^']+)'", classifier)
    go_pattern = re.search(r"versionDirPattern\s*= regexp.MustCompile\(`([^`]+)`\)", store)
    assert ps_pattern and go_pattern
    assert ps_pattern.group(1) == go_pattern.group(1)
    pattern = re.compile(ps_pattern.group(1))
    name = "v1-AKADPAK8-b-01M4VBXHT0DS0QNK83AKADPAK8"
    assert pattern.fullmatch(name)
    assert not pattern.fullmatch("v1-AKADPAK8-b-not-a-receipt")
    assert "($RelativePath -cne $top -or $IsDirectory)" in classifier
    assert "if ($IsDirectory) { return 'BundleVersionDirectory' }" in classifier
    assert "return 'BundleVersionFile'" in classifier
    builder = _extract_function_body(
        module,
        "function New-DefenseClawCanonicalPathAcl",
        "function Test-DefenseClawExactRawDACL",
    )
    assert "$versionServiceReadOnly = $Kind -eq 'BundleVersionDirectory' -and" in builder
    assert "-not $versionServiceReadOnly" in builder
    for kind in ("BundleVersionDirectory", "BundleVersionFile"):
        entry = builder.split(f"        '{kind}' {{", 1)[1].split("\n        }", 1)[0]
        assert "rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute" in entry
        assert "$script:UsersSID" not in entry

    sid = "S-1-5-80-1-2-3-4-5"

    def creator_sddl(function: str, inherit: str = "") -> str:
        body = go_acl.split(f"func {function}(", 1)[1].split("\n}", 1)[0]
        expression = re.search(r"^\s*return (.+)$", body, re.MULTILINE)
        assert expression
        parts = re.findall(r'"[^"]*"|\b(?:inherit|serviceSID)\b', expression.group(1))
        assert re.sub(r'"[^"]*"|\b(?:inherit|serviceSID)\b|[+\s]', "", expression.group(1)) == ""
        return "".join(
            {"inherit": inherit, "serviceSID": sid}[part]
            if part in {"inherit", "serviceSID"} else json.loads(part)
            for part in parts
        )

    creators = {
        "BundleDirectory": creator_sddl("windowsBundleDirectorySDDL"),
        "BundleReceipt": creator_sddl("windowsBundleReceiptSDDL"),
        "BundleVersionDirectory": creator_sddl("windowsBundleVersionSDDL", "OICI"),
        "BundleVersionFile": creator_sddl("windowsBundleVersionSDDL"),
        "AdminDirectory": creator_sddl("windowsBundlePrivateSDDL"),
        "AdminFile": creator_sddl("windowsBundleAdminFileSDDL"),
    }
    assert 'inherit = "OICI"' in go_acl.split("func windowsBundleVersionSDDL(", 1)[1].split("\n}", 1)[0]
    for kind, actual in creators.items():
        expected = re.search(rf"^\s*{kind} = ([\"'])(.*?)\1", smoke, re.MULTILINE)
        assert expected, kind
        assert actual == expected.group(2).replace("$serviceSID", sid), kind
        assert "D:P" in actual, kind
        assert all("ID" not in ace.split(";", 2)[1] for ace in re.findall(r"\([^)]*\)", actual)), kind
        if kind.startswith("BundleVersion"):
            assert ";;;BU)" not in actual
            assert f";;;{sid})" in actual
            assert "0x1200a9" in actual
    assert "$versionName = 'v1-AKADPAK8-b-01M4VBXHT0DS0QNK83AKADPAK8'" in smoke
    assert "Get-DefenseClawBundlePathKind -RelativePath $Relative" in smoke
    assert "Kind = 'AdminDirectory'" in module.split("function Invoke-DefenseClawBundleAclContract {", 1)[1].split("function Set-DefenseClawManagedAcls {", 1)[0]
    assert "store.EnsurePrivateDirectory = windowsBundleEnsurePrivateDirectory" in go
    assert "store.PublishPrivateFile = windowsBundlePublishPrivateFile" in go
    assert "return createWindowsBundleDirectory(path, windowsBundlePrivateSDDL())" in go
    assert "return applyWindowsBundleSDDL(path, windowsBundleAdminFileSDDL())" in go
    assert "store.EnsureStageDirectory = windowsBundleEnsureStageDirectory" in go
    assert "store.PublishStageFile = windowsBundlePublishStageFile" in go
    assert "windowsBundleEnsurePrivateDirectory(filepath.Dir(dst))" in go
    # The anchors are replaced, then sealed admin-only (w3-g3-obs splits the
    # two steps so a failed seal is recorded as a changed file).
    assert "writeWindowsBundleFile(dst, raw)" in go
    assert "windowsBundlePublishPrivateFile(dst)" in go
    assert "'trust'" in module.split("function Invoke-DefenseClawBundleAclContract {", 1)[1].split("function Set-DefenseClawManagedAcls {", 1)[0]
    assert "s.EnsureStageDirectory(dir, parent)" in store
    assert "if !dirs[parent]" in store
    assert "s.PublishStageFile(full)" in store
    assert "windows.CreateDirectory(name, attributes)" in go
    assert "createWindowsBundleDirectoryMode" not in go
    assert "windows.FILE_FLAG_OPEN_REPARSE_POINT" in go
    assert "windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityInfo)" in go
    assert "windows.OWNER_SECURITY_INFORMATION |" in go
    assert "windowsEnterpriseSIDEqual(actualOwner, owner)" in go
    assert "windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT," in go
    assert "windows.PROTECTED_DACL_SECURITY_INFORMATION" in go


def test_public_receipt_event_paths_select_public_exact_acl() -> None:
    source = MODULE.read_text(encoding="utf-8")
    classifier = _extract_function_body(
        source,
        "function Get-DefenseClawBundlePathKind",
        "function Invoke-DefenseClawBundleAclContract",
    )
    event_branch = classifier.split("if ($top -ceq 'receipt-events') {", 1)[1].split(
        "# The immutable name", 1,
    )[0]
    assert "if ($RelativePath -ceq $top -and $IsDirectory)" in event_branch
    assert "return 'BundleDirectory'" in event_branch
    assert "-not $IsDirectory" in event_branch
    assert "return 'BundleReceipt'" in event_branch
    pattern = re.search(r"\$RelativePath -cmatch '([^']+)'", event_branch)
    assert pattern
    cases = {
        r"receipt-events\b-01JA0000000000000000000033.json": True,
        r"receipt-events\r-01JA0000000000000000000033.json": True,
        r"receipt-events\invalid.json": False,
        r"receipt-events\nested\b-01JA0000000000000000000033.json": False,
    }
    for path, public_receipt in cases.items():
        assert (re.fullmatch(pattern.group(1), path) is not None) is public_receipt, path

    builder = _extract_function_body(
        source,
        "function New-DefenseClawCanonicalPathAcl",
        "function Test-DefenseClawExactRawDACL",
    )
    for kind, right in (("BundleDirectory", "ReadAndExecute"), ("BundleReceipt", "Read")):
        entry = builder.split(f"        '{kind}' {{", 1)[1].split("\n        }", 1)[0]
        assert "$script:UsersSID" in entry
        assert f"[Security.AccessControl.FileSystemRights]::{right}" in entry

    smoke = SMOKE.read_text(encoding="utf-8")
    for path, kind in (
        ("receipt-events", "BundleDirectory"),
        (r"receipt-events\b-01JA0000000000000000000033.json", "BundleReceipt"),
        (r"receipt-events\invalid.json", "AdminFile"),
    ):
        assert f"relative = '{path}'; directory = $" in smoke
        assert f"kind = '{kind}'" in smoke.split(f"relative = '{path}'", 1)[1].split("}", 1)[0]

    go = WINDOWS_BUNDLE.read_text(encoding="utf-8")
    go_acl = WINDOWS_BUNDLE_ACL.read_text(encoding="utf-8")
    store = GO_STORE.read_text(encoding="utf-8")
    assert "store.EnsurePublicReceiptEventsDirectory = ensureWindowsBundlePublicReceiptEventsDirectory" in go
    assert "ensureErr = s.EnsurePublicReceiptEventsDirectory(eventsDir)" in store
    public_dir = go_acl.split("func windowsBundleDirectorySDDL(", 1)[1].split("\n}", 1)[0]
    public_file = go_acl.split("func windowsBundleReceiptSDDL(", 1)[1].split("\n}", 1)[0]
    assert ";;;BU)" in public_dir and ";;;BU)" in public_file
    setup_ensure = go.split("func ensureWindowsBundleReceiptEvents(", 1)[1].split("\n}", 1)[0]
    publisher = go.split("func publishWindowsBundleReceipt(", 1)[1].split("\n}", 1)[0]
    assert "windowsBundleDirectorySDDL(" in setup_ensure
    assert "windowsBundleReceiptSDDL(" in setup_ensure
    assert "windowsBundleDirectorySDDL(" in publisher
    assert "windowsBundleReceiptSDDL(" in publisher
    assert "windowsBundlePrivateSDDL()" not in setup_ensure + publisher
    assert "windowsBundleAdminFileSDDL()" not in publisher


def test_uninstall_removes_only_its_gateway_sid_from_the_shared_ipc_dacl() -> None:
    source = MODULE.read_text(encoding="utf-8")
    matcher = _extract_function_body(
        source,
        "function Remove-DefenseClawSIDFromRawDACL",
        "function Resolve-DefenseClawRetiredGatewayServiceSID",
    )
    resolver = _extract_function_body(
        source,
        "function Resolve-DefenseClawRetiredGatewayServiceSID",
        "function Revoke-DefenseClawManagedIPCServiceAccess",
    )
    cleanup = _extract_function_body(
        source,
        "function Revoke-DefenseClawManagedIPCServiceAccess",
        "function Invoke-DefenseClawBundleAclContract",
    )
    descriptor_guard = _extract_function_body(
        source,
        "function Assert-DefenseClawManagedIPCRetirementDescriptor",
        "function Revoke-DefenseClawManagedIPCServiceAccess",
    )
    assert "[Security.AccessControl.CommonAce]" in matcher
    assert "[Security.AccessControl.AceQualifier]::AccessAllowed" in matcher
    assert "[Security.AccessControl.AceFlags]::None" in matcher
    assert "[Security.AccessControl.FileSystemRights]::FullControl" in matcher
    assert "$matchingIndexes.Count -ne 1" in matcher
    assert "duplicate ACEs" in matcher
    assert "non-canonical ACE" in matcher
    assert "Get-DefenseClawServiceSIDForRecovery" in resolver
    assert "Resolve-DefenseClawRetiredGatewayServiceSID" in cleanup
    assert "Remove-DefenseClawSIDFromRawDACL" in cleanup
    assert "GetDirectorySecuritySnapshotNoFollowIfExists" in cleanup
    assert "SetDirectoryDaclNoFollow" in cleanup
    assert "$expectedDescriptor.GetBinaryForm($expectedBytes, 0)" in cleanup
    assert "$expectedDescriptor.GetSddlForm" not in cleanup
    assert "Microsoft.PowerShell.Management\\Test-Path" not in cleanup
    assert "$resolvedSID" not in descriptor_guard
    assert "$script:SystemSID" in descriptor_guard
    assert "$script:AdministratorsSID" in descriptor_guard
    assert "$script:TrustedInstallerSID" in descriptor_guard
    assert "[string]$before.Identity" in cleanup
    assert "Test-DefenseClawExactRawDACL" in cleanup
    assert "PurgeAccessRules" not in cleanup
    assert "Set-DefenseClawPathAcl" not in cleanup
    assert "Remove-Item" not in cleanup
    zero_match = cleanup.index("if ([int]$filtered.removed -eq 0)")
    assert cleanup.rfind(
        "Test-DefenseClawServiceExists",
        0,
        zero_match,
    ) >= cleanup.index("$filtered = Remove-DefenseClawSIDFromRawDACL")
    assert cleanup.rfind("Test-DefenseClawServiceExists") > cleanup.index(
        "$publishedDescriptor =",
    )

    native_open = _extract_function_body(
        source,
        "private static IntPtr OpenDirectorySecurity",
        "GetDirectorySecuritySnapshotNoFollow",
    )
    native_set = _extract_function_body(
        source,
        "public static PathSecuritySnapshot SetDirectoryDaclNoFollow",
        "SetRegularFileSecurityDescriptorNoFollow",
    )
    assert "bool shareDelete" in native_open
    assert "(shareDelete ? FILE_SHARE_DELETE : 0)" in native_open
    assert "false,\n                    out before" in native_set

    purge = _extract_function_body(
        source,
        "function Complete-DefenseClawStatePurge",
        "function Invoke-DefenseClawCommittedUninstallCleanup",
    )
    committed = _extract_function_body(
        source,
        "function Invoke-DefenseClawCommittedUninstallCleanup",
        "function Invoke-DefenseClawPreLayoutRecovery",
    )
    assert "Revoke-DefenseClawManagedIPCServiceAccess" in purge
    assert "-GatewayServiceSID $GatewayServiceSID" in purge
    assert purge.count("Get-DefenseClawManagedServiceNames") >= 2
    assert purge.rfind("Get-DefenseClawManagedServiceNames") > purge.index(
        "Revoke-DefenseClawManagedIPCServiceAccess",
    )
    assert "Revoke-DefenseClawManagedIPCServiceAccess" in committed


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
    # The read-only precheck before the stops (GAP-0920) refuses a bad key
    # early; the snapshot the transaction records is taken after them.
    capture_at = transaction.index("$redactionKeySecurity =")
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
    descriptor_count = payload.pop("descriptors_checked")
    pairing_count = payload.pop("installer_verifier_pairings_checked")
    # The smoke script checks its descriptor kinds against both module
    # ValidateSet declarations and its installer/verifier pairing table.
    assert isinstance(descriptor_count, int) and descriptor_count > 0
    assert pairing_count == descriptor_count
    assert payload == {
        "ok": True,
        "schema_version": 1,
        "stale_explicit_aces_retained": False,
        "object_type_mismatches_rejected": True,
        "auto_inherited_control_flag_accepted": True,
        "ace_mismatches_rejected": True,
        "native_raw_acl_query_checked": True,
        "split_explicit_aces_rejected": True,
        "acl_kind_sets_agree": True,
        "state_ancestor_grant_is_additive": True,
        "managed_ipc_scope_cleanup_exact": True,
        "managed_ipc_other_service_ace_preserved": True,
        "managed_ipc_cleanup_idempotent": True,
        "managed_ipc_next_scope_canonical": True,
        "managed_ipc_native_handle_cleanup": True,
        "managed_ipc_noncanonical_target_aces_rejected": True,
        "managed_ipc_retired_sid_owner_group_rejected": True,
        "retained_runtime_tree_adopted": True,
        "retained_runtime_hard_links_rejected": True,
        "retained_runtime_secret_acl_exact": True,
        "retained_runtime_secret_bytes_preserved": True,
        "retained_runtime_secret_hash_preserved": True,
        "retained_runtime_secret_identity_preserved": True,
    }
