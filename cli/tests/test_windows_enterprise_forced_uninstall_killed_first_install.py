# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""p0-round:GAP-1365: the first forced uninstall after a killed first install.

A first install killed before it wrote deployment.json leaves StateRoot with a
pending transaction and no record. The uninstall read that as untrusted
deployment evidence and took the metadata-free purge, which refuses to bypass
the transaction: the first Setup /uninstall FORCE=1 ended 1603 and only a
retry finished. A forced uninstall with no record now goes straight on as the
forced uninstall. An existing but untrusted record still takes the
metadata-free purge, and nothing changes without FORCE.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"

HARNESS = r"""
param([string]$ModulePath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$null, [ref]$errors)
if ($errors.Count -gt 0) { throw $errors[0].Message }
$definition = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Test-DefenseClawUninstallUsesUntrustedMetadataPurge'
}, $true)
. ([ScriptBlock]::Create($definition.Extent.Text))
$missing = 'deployment.json is missing from an existing StateRoot'
$cases = @(
    @{ name = 'force-no-record'; reason = $missing; exists = $false; force = $true; want = $false },
    @{ name = 'no-force-no-record'; reason = $missing; exists = $false; force = $false; want = $true },
    @{ name = 'force-untrusted-record'; reason = 'deployment.json has a foreign owner'; exists = $true; force = $true; want = $true },
    @{ name = 'trusted'; reason = ''; exists = $true; force = $true; want = $false },
    @{ name = 'trusted-no-force'; reason = ''; exists = $false; force = $false; want = $false }
)
foreach ($case in $cases) {
    $got = Test-DefenseClawUninstallUsesUntrustedMetadataPurge -Reason $case.reason -MetadataExists $case.exists -Force:$case.force
    "$($case.name)=$got want=$($case.want)"
}
"""


def _pwsh() -> str | None:
    return shutil.which("pwsh")


def test_the_lifecycle_routes_untrusted_evidence_through_the_decision() -> None:
    text = MODULE.read_text(encoding="utf-8")
    call = text.index("if (Test-DefenseClawUninstallUsesUntrustedMetadataPurge `")
    following = text[call : call + 600]
    assert "-MetadataExists $uninstallMetadataExists" in following
    assert "-Force:$Force" in following
    assert "return Invoke-DefenseClawUntrustedMetadataRecoveryPurge" in following
    # The forced uninstall comes after the decision, so a forced run with no
    # record reaches it instead of the metadata-free purge.
    assert text.index("return Invoke-DefenseClawForcedUninstall `", call) > call


@pytest.mark.skipif(_pwsh() is None, reason="PowerShell 7 is not installed")
def test_a_forced_uninstall_with_no_record_skips_the_metadata_free_purge(tmp_path: Path) -> None:
    harness = tmp_path / "harness.ps1"
    harness.write_text(HARNESS, encoding="utf-8")
    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(harness), "-ModulePath", str(MODULE)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    lines = [line.strip() for line in result.stdout.splitlines() if "=" in line]
    assert len(lines) == 5, result.stdout
    for line in lines:
        name, rest = line.split("=", 1)
        got, want = rest.split(" want=")
        assert got == want, f"{name}: got {got}, want {want}"
