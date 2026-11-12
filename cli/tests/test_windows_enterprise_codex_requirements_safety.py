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
$script:DefenseClawRollbackDeferBusyWriter = $false
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


def test_the_rebuild_renders_beside_the_file_and_never_swaps_a_base_over_it() -> None:
    text = _text()
    repair = _function_body(text, "Repair-DefenseClawRecoveredCodexRequirements")
    # Nothing is swapped over the live path by PowerShell: no placeholder, no
    # restore. The gateway renders the preimage into the managed policy beside
    # the file, checks it (it parses and carries every managed hook) and swaps
    # the result in, or leaves the file as it was.
    assert "Install-DefenseClawFileAtomic" not in repair
    assert "-BaseFile $staged" in repair
    capability = repair.index("-Capability codex_requirements_base_file")
    assert capability < repair.index("-BaseFile $staged")
    assert "cannot render the managed policy beside the file" in repair
    assert repair.count("the file was left as it was") >= 2
    assert "# DefenseClaw managed Codex requirements" not in repair
    command = _function_body(text, "Invoke-DefenseClawCodexRequirementsCommand")
    assert "'--base-file', $BaseFile" in command
    assert "$BaseFile -ne '' -and $Action -cne 'reconcile'" in command


def test_the_publishable_check_refuses_empty_bom_nul_and_non_text() -> None:
    check = _function_body(_text(), "Assert-DefenseClawCodexRequirementsPublishable")
    for needle in ("$Bytes.Length -eq 0", "IndexOf($Bytes, [byte]0)", "UTF8Encoding]::new($false, $true)", "TrimStart([char]0xFEFF)"):
        assert needle in check, needle


def test_a_writer_lock_failure_is_classified_by_its_error_code_not_only_by_text() -> None:
    text = _text()
    command = _function_body(text, "Invoke-DefenseClawCodexRequirementsCommand")
    assert "$reportedCode -ceq 'writer_lock_busy'" in command
    go = (ROOT / "internal" / "gateway" / "connector" / "codex_machine_requirements_windows.go").read_text(encoding="utf-8")
    assert go.count("windowsCodexWriterLockBusyError{") >= 3
    # GAP-1001 review D3: named classifiers by Win32 code, behavior-tested in the connector package.
    assert go.count("windowsCodexLockRangeBusy(err)") == 2 and go.count("windowsCodexLockOpenBusy(err)") == 2
    assert "errors.Is(err, windows.ERROR_IO_PENDING)" in go
    cli = (ROOT / "internal" / "cli" / "windows_codex_requirements.go").read_text(encoding="utf-8")
    assert "annotateWindowsCodexRequirementsFailure(&report, err)" in cli
    neutral = (ROOT / "internal" / "cli" / "windows_codex_requirements_basefile.go").read_text(encoding="utf-8")
    assert "report.ErrorCode = windowsCodexRequirementsWriterLockBusyCode" in neutral
    assert '"--base-file"' not in cli and 'StringVar(&baseFile, "base-file"' in cli


def test_the_rollback_never_swaps_an_unguarded_requirements_file_over_a_guarded_one() -> None:
    text = _text()
    problem = _function_body(text, "Get-DefenseClawCodexRequirementsGuardProblem")
    for needle in ("Assert-DefenseClawCodexRequirementsPublishable -Bytes $Bytes", "[[hooks.", "defenseclaw-hook"):
        assert needle in problem.replace("\\[\\[\\s*hooks\\.", "[[hooks."), needle
    restore = _function_body(text, "Restore-DefenseClawTransaction")
    guard = restore.index("Get-DefenseClawCodexRequirementsGuardProblem -Bytes ([IO.File]::ReadAllBytes($backup))")
    assert restore.index("$isCodexMachinePolicy -and (Test-DefenseClawStandaloneProfile)") < guard
    assert guard < restore.index("-Source $backup", guard)
    assert "$backupProblem -ne '' -and $currentProblem -eq ''" in restore
