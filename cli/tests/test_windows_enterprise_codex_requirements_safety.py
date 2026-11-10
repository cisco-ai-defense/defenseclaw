r"""GAP-1001 (r109, P1): a Codex requirements.toml must never be left empty.

With a Codex writer holding the writer lock, the gateway's Codex commands fail
with a lock-busy answer. The GAP-0955 forward recovery read that as a hand edit
of the policy, rebuilt requirements.toml from an empty base and, when the
reconcile that follows failed too, left a 0-byte file: Codex then loads no
DefenseClaw hook or policy at all and runs unguarded. The recovery now tells a
busy writer apart from a policy defect, never swaps in an empty or non-UTF-8
file, puts the original bytes back when a rebuild fails, and verify names an
empty file as leaving Codex unguarded. Standalone only.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"


def _text() -> str:
    return MODULE.read_text(encoding="utf-8")


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case, [int]$Standalone = 1)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Test-DefenseClawCodexWriterLockBusyMessage', 'New-DefenseClawCodexWriterBusyRefusal')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing $name" }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
function Format-DefenseClawSetupAction { param([string]$Action) "Setup $Action" }
function Get-DefenseClawCodexWriterHolderText { param([string]$Path) 'the writer is writer.exe (pid 4242, account NT AUTHORITY\SYSTEM)' }
$layout = @{ CodexManagedHooksStatePath = (Join-Path $Scratch '.defenseclaw-managed-hooks.state') }
$busy = @(
    'Codex requirements reconcile failed: timed out waiting 10s for Codex machine policy lock',
    'Codex requirements verify failed: open Codex machine policy lock: The process cannot access the file because it is being used by another process.',
    'open Codex machine policy lock: sharing violation'
)
$notBusy = @(
    'Codex requirements reconcile failed: allow_managed_hooks_only=false conflicts with required isolation',
    'Codex requirements verify failed: hooks.SessionStart has no DefenseClaw managed group',
    'acquire Codex machine policy lock: Access is denied.',
    ''
)
[ordered]@{
    busy = @($busy | ForEach-Object { [bool](Test-DefenseClawCodexWriterLockBusyMessage -Message $_) })
    notBusy = @($notBusy | ForEach-Object { [bool](Test-DefenseClawCodexWriterLockBusyMessage -Message $_) })
    refusal = New-DefenseClawCodexWriterBusyRefusal -Layout $layout -Action 'reconcile' -Detail $busy[0]
} | ConvertTo-Json -Compress -Depth 4
"""


def _run(tmp_path: Path) -> dict:
    engine = shutil.which("pwsh")
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "codex-requirements-safety.ps1"
    harness.write_text(_HARNESS, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Scratch", str(scratch), "-Case", "busy"],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_a_busy_writer_lock_is_told_apart_from_a_defect_of_the_policy_file(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result["busy"] == [True, True, True], result
    assert result["notBusy"] == [False, False, False, False], result
    refusal = result["refusal"]
    assert refusal.startswith("codex_state_unsettled: a Codex writer holds the writer lock next to "), result
    assert "the writer is writer.exe (pid 4242, account NT AUTHORITY\\SYSTEM)" in refusal, result
    assert "run Setup /repair again once no Codex writer is running" in refusal, result
    assert "timed out waiting 10s for Codex machine policy lock" in refusal, result
    assert "FORCE" not in refusal, result


def test_a_busy_writer_never_reaches_the_recovery_that_rebuilds_the_policy_file() -> None:
    text = _text()
    command = _function_body(text, "Invoke-DefenseClawCodexRequirementsCommand")
    assert command.index("Test-DefenseClawStandaloneProfile") < command.index("New-DefenseClawCodexWriterBusyRefusal")
    assert command.index("New-DefenseClawCodexWriterBusyRefusal") < command.index('throw "Codex requirements $Action failed: $detail"')
    forward = _function_body(text, "Invoke-DefenseClawCodexRequirementsReconcileOrRecover")
    assert forward.index("codex_state_unsettled: ") < forward.index("Repair-DefenseClawRecoveredCodexRequirements")
    repair = _function_body(text, "Repair-DefenseClawRecoveredCodexRequirements")
    # The file is judged and touched only after the busy answers are told apart.
    assert repair.index("$verifyError.StartsWith('codex_state_unsettled: '") < repair.index("$backupPath = ''")
    assert repair.index("$mergeError.StartsWith('codex_state_unsettled: '") < repair.index("Get-DefenseClawRecordedCodexRequirementsPreimage")
    assert "throw $verifyError" in repair and "throw $mergeError" in repair


def test_a_rebuild_never_swaps_in_an_empty_or_unpublishable_requirements_file() -> None:
    text = _text()
    check = _function_body(text, "Assert-DefenseClawCodexRequirementsPublishable")
    for needle in ("$Bytes.Length -eq 0", "IndexOf($Bytes, [byte]0)", "UTF8Encoding]::new($false, $true)", "IsNullOrWhiteSpace($text)"):
        assert needle in check, needle
    repair = _function_body(text, "Repair-DefenseClawRecoveredCodexRequirements")
    guard = repair.index("Assert-DefenseClawCodexRequirementsPublishable -Bytes $base")
    assert repair.index("# GAP-1001: the base is never an empty file") < guard < repair.index("[IO.File]::WriteAllBytes($staged, $base)")
    assert guard < repair.index("Install-DefenseClawFileAtomic -Source $staged -Destination $path")


def test_a_failed_rebuild_puts_the_original_requirements_file_back_through_the_same_swap() -> None:
    # GAP-1001: the rebuild writes a base through a sibling and a swap; when the
    # reconcile that follows fails, the bytes read first go back the same way,
    # so no empty or partial file stays in place of the one the recovery found.
    repair = _function_body(_text(), "Repair-DefenseClawRecoveredCodexRequirements")
    assert "$edited = $null" in repair
    rebuild = repair.index("$rebuildError = [string]$_.Exception.Message")
    window = repair[rebuild : rebuild + 1800]
    assert "[IO.File]::WriteAllBytes($restoreStaged, $edited)" in window
    assert "Install-DefenseClawFileAtomic -Source $restoreStaged -Destination $path" in window
    assert "the file was left as it was" in window
    assert window.index("Install-DefenseClawFileAtomic") < window.index("throw (\"Codex requirements recovery could not republish")
