r"""GAP-1732: a standalone reinstall after Intune or an administrator edited the
machine Codex requirements.toml (or the Claude 90-defenseclaw.json drop-in)
no longer fails 1603.

Get-DefenseClawSharedManagedHookOwners only decides which DefenseClaw scope
owns the shared machine hook files. When the file its protected state record
binds changed or was removed after DefenseClaw wrote it, the probe threw on
the standalone profile, and Setup /install failed for every user. The writer
re-merges and re-authenticates the file later in the same transaction, so the
refusal protected nothing. Outside strict mode both profiles now keep the
owner and log defenseclaw_accept with the pinned and live hashes; strict mode
keeps refusing.

The harness runs the real function from the module (extracted from its AST)
under PowerShell 7 with its file-security helpers stubbed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"

_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [int]$Standalone, [int]$Strict)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
class FakeNativeSecurity {
    static [object] GetRegularFileSecuritySnapshotNoFollowIfExists([string]$Path) {
        if ([IO.File]::Exists($Path)) { return 'snapshot' }
        return $null
    }
}
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
$definition = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-DefenseClawSharedManagedHookOwners'
}, $true)
if ($null -eq $definition) { throw 'missing Get-DefenseClawSharedManagedHookOwners' }
. ([ScriptBlock]::Create($definition.Extent.Text))
$script:ProgramData = Join-Path $Scratch 'ProgramData'
$script:ProgramFiles = Join-Path $Scratch 'ProgramFiles'
$script:events = [Collections.Generic.List[string]]::new()
function Test-DefenseClawStandaloneProfile { [bool]$Standalone }
function Test-DefenseClawTrustStrictAncestors { [bool]$Strict }
function Initialize-DefenseClawNativeSecurity { [FakeNativeSecurity] }
function Resolve-DefenseClawCodexManagedHooksStateCopySettled { param([switch]$Strict, [string]$Path) $Path }
function Assert-DefenseClawNoReparsePath { param([string]$Path, [switch]$AllowMissingLeaf) }
function Assert-DefenseClawSharedHookProbeAcl { param([string]$Path) }
function Write-DefenseClawResilienceEvent { param([string]$Marker, [hashtable]$Fields) $script:events.Add($Marker + ': ' + $Fields['reason']) }
$layout = @{
    CodexManagedHooksStatePath = (Join-Path $Scratch 'codex/.defenseclaw-managed-hooks.state')
    CodexMachinePolicyPath = (Join-Path $Scratch 'codex/requirements.toml')
}
$threw = ''
$owners = @()
try { $owners = @(Get-DefenseClawSharedManagedHookOwners -Layout $layout) }
catch { $threw = $_.Exception.Message }
[pscustomobject]@{ threw = $threw; owners = @($owners); events = @($script:events) } | ConvertTo-Json -Compress
"""

_WRITTEN = b"[features]\ncodex_hooks = true\n"


def _run(tmp_path: Path, case: str, standalone: bool, strict: bool) -> dict:
    engine = shutil.which("pwsh")
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    scratch = tmp_path / "scratch"
    codex = scratch / "codex"
    codex.mkdir(parents=True)
    (scratch / "ProgramData").mkdir()
    (scratch / "ProgramFiles").mkdir()
    policy = codex / "requirements.toml"
    policy.write_bytes(_WRITTEN)
    (codex / ".defenseclaw-managed-hooks.state").write_text(
        json.dumps(
            {"gateway_service_name": "DefenseClawGateway", "requirements_sha256": hashlib.sha256(_WRITTEN).hexdigest()}
        ),
        encoding="utf-8",
    )
    if case == "edited":
        policy.write_bytes(_WRITTEN + b'# added by Intune\n[otel]\nexporter = "none"\n')
    elif case == "removed":
        policy.unlink()
    harness = tmp_path / "shared-hook-owner.ps1"
    harness.write_text(_HARNESS, encoding="utf-8")
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
            "-ModulePath",
            str(MODULE),
            "-Scratch",
            str(scratch),
            "-Standalone",
            "1" if standalone else "0",
            "-Strict",
            "1" if strict else "0",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("case", ["edited", "removed"])
@pytest.mark.parametrize("standalone", [True, False], ids=["standalone", "secure-client"])
def test_a_changed_or_removed_bound_file_keeps_its_owner_outside_strict(
    tmp_path: Path, case: str, standalone: bool
) -> None:
    result = _run(tmp_path, case, standalone=standalone, strict=False)
    assert result["threw"] == "", result
    assert result["owners"] == ["DefenseClawGateway"], result
    assert len(result["events"]) == 1 and result["events"][0].startswith("defenseclaw_accept: Codex "), result


@pytest.mark.parametrize("case", ["edited", "removed"])
@pytest.mark.parametrize("standalone", [True, False], ids=["standalone", "secure-client"])
def test_strict_mode_keeps_refusing(tmp_path: Path, case: str, standalone: bool) -> None:
    result = _run(tmp_path, case, standalone=standalone, strict=True)
    assert "managed-hook ownership" in result["threw"], result
    assert result["events"] == [], result


def test_an_intact_binding_counts_without_an_event(tmp_path: Path) -> None:
    result = _run(tmp_path, "intact", standalone=True, strict=False)
    assert result == {"threw": "", "owners": ["DefenseClawGateway"], "events": []}, result
