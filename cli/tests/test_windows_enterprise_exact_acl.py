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
SMOKE = (
    ROOT
    / "packaging"
    / "windows"
    / "tests"
    / "enterprise-exact-acl-smoke.ps1"
)


def _powershell_engines() -> list[str]:
    candidates: list[str | None] = [
        shutil.which("powershell.exe"),
        shutil.which("pwsh.exe"),
    ]
    windows_root = os.environ.get("SystemRoot")
    if windows_root:
        candidates.append(
            str(
                Path(windows_root)
                / "System32"
                / "WindowsPowerShell"
                / "v1.0"
                / "powershell.exe"
            )
        )

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


def test_canonical_setter_replaces_the_entire_protected_dacl() -> None:
    source = MODULE.read_text(encoding="utf-8")
    setter = source[
        source.index("function New-DefenseClawCanonicalPathAcl") :
        source.index("function Set-DefenseClawBootstrapRootAcl")
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
        setter.index("function Assert-DefenseClawCanonicalPathAcl") :
        setter.index("function Set-DefenseClawPathAcl")
    ]
    assert "GetSecurityDescriptorSddlForm" not in assertion
    assert "GetFileSecurityDescriptor" in assertion
    assert "Test-DefenseClawExactRawDACL" in assertion
    assert "Get-Acl" not in assertion
    assert "$ownerSID -ne $script:AdministratorsSID" in assertion
    assert "$groupSID -ne $script:AdministratorsSID" in assertion
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
        source.index("function Add-DefenseClawStateAncestorTraverseRule") :
        source.index("function Assert-DefenseClawStateAncestorTraverse")
    ]

    assert "PurgeAccessRules" in grant
    assert "InheritanceFlags]::None" in grant
    assert "Get-Acl" in grant
    # The canonical builder replaces the owner and the whole DACL.
    assert "New-DefenseClawCanonicalPathAcl" not in grant
    assert "Set-DefenseClawPathAcl" not in grant
    assert "SetAccessRuleProtection" not in grant
    assert "SetOwner" not in grant

    applied = source[
        source.index("foreach ($ancestor in @($Layout.StateRootAncestors)) {") :
    ]
    assert "Grant-DefenseClawStateAncestorTraverse" in applied

    # The ancestor trust invariant still has to hold.
    verifier = source[
        source.index("function Assert-DefenseClawStateAncestorTraverse") :
        source.index("function Initialize-DefenseClawManagedRoot")
    ]
    assert "Assert-DefenseClawTrustedAncestor" in verifier
    assert "must not " in verifier
    assert "cannot traverse an ancestor of " in verifier

    # The base is an OS directory and the root carries its own DACL, so neither
    # appears in the ancestor list.
    ancestors = source[
        source.index("function Get-DefenseClawManagedRootAncestors") :
        source.index("$script:StateAncestorTraverseRights")
    ]
    assert "$index -lt $components.Count - 1" in ancestors


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell smoke")
@pytest.mark.parametrize("engine", _powershell_engines())
def test_every_managed_path_kind_has_an_exact_descriptor(engine: str) -> None:
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
        "descriptors_checked": 16,
        "stale_explicit_aces_retained": False,
        "object_type_mismatches_rejected": True,
        "auto_inherited_control_flag_accepted": True,
        "ace_mismatches_rejected": True,
        "native_raw_acl_query_checked": True,
        "split_explicit_aces_rejected": True,
        "installer_verifier_pairings_checked": 16,
        "acl_kind_sets_agree": True,
        "state_ancestor_grant_is_additive": True,
    }
