r"""GAP-0877: a check of the Codex managed runtime state does not call a
state missing while a Codex writer transaction is open.

The writer (the hook guardian, a Setup step) makes the transaction counter
(the size of .defenseclaw-managed-hooks.writer.lock) odd while it runs and the
next even value, with the hook copy .defenseclaw-managed-hooks.state.<n> in
place, when it ends, even when nothing changed. A check that looked in between
resolved the copy of the odd counter plus one, which does not exist yet, and
failed 1603 "state is missing". It now waits, bounded, for an even counter
that is the same before and after it looks at the copy, and a counter that
stays odd or keeps moving refuses with the named codex_state_unsettled.

Review S1: the other callers that resolve the copy from the counter (the
metadata record, the shared-hook owner probe, the ACL stamp, the content gate,
the preflight, the check that the state is gone) read it through the same wait.
"""

from __future__ import annotations

import json
import re
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


def test_every_state_check_goes_through_the_one_wait() -> None:
    text = _text()
    body = _function_body(text, "Assert-DefenseClawCodexManagedHooksStateFile")
    assert "Wait-DefenseClawCodexManagedHooksStateSettled" in body
    assert "Resolve-DefenseClawCodexManagedHooksStateCopy" not in body
    # Setup verification after an install, a repair, an ensure or an upgrade,
    # and the reconcile, all call that one assert.
    assert text.count("Assert-DefenseClawCodexManagedHooksStateFile -Layout $Layout") >= 3


# Every function that resolves the Codex hook copy of the state, with how:
# "strict" refuses a writer that never settles by name, "soft" falls back to
# the plain resolver, as before the wait (the verify step refuses it).
_SETTLED_CALLERS = {
    "New-DefenseClawDeploymentMetadata": "strict",
    "Get-DefenseClawSharedManagedHookOwners": "strict",
    "Set-DefenseClawManagedAcls": "soft",
    "Assert-DefenseClawStandaloneContentTrusted": "soft",
    "Assert-DefenseClawCodexManagedHooksStateFilePreflight": "soft",
    "Complete-DefenseClawCodexRequirementsRemoval": "soft",
}
# The plain resolver is kept where the name is computed to be written, or the
# writer is stopped (each has a comment saying why).
_PLAIN_RESOLVER_FUNCTIONS = {
    "Resolve-DefenseClawCodexManagedHooksStateCopy",
    "Resolve-DefenseClawCodexManagedHooksStateCopySettled",
    "Sync-DefenseClawCodexManagedHooksStateCopy",
    "Restore-DefenseClawForcedUninstallCodexPolicy",
}


def _functions_calling(text: str, needle: str) -> dict[str, str]:
    """name -> the text of the function, for every function that mentions needle."""
    found: dict[str, str] = {}
    starts = [(m.start(), m.group(1)) for m in re.finditer(r"(?m)^function ([A-Za-z0-9-]+) \{$", text)]
    for index, (start, name) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(text)
        if needle in text[start:end]:
            found[name] = text[start:end]
    return found


def test_every_caller_that_resolves_the_copy_from_the_counter_waits_for_the_writer() -> None:
    text = _text()
    plain = _functions_calling(text, "Resolve-DefenseClawCodexManagedHooksStateCopy -Path")
    assert set(plain) == _PLAIN_RESOLVER_FUNCTIONS - {"Resolve-DefenseClawCodexManagedHooksStateCopy"}, sorted(plain)
    for name in ("Sync-DefenseClawCodexManagedHooksStateCopy", "Restore-DefenseClawForcedUninstallCodexPolicy"):
        assert "The plain resolver, on purpose (GAP-0877" in plain[name], name
    settled = _functions_calling(text, "Resolve-DefenseClawCodexManagedHooksStateCopySettled")
    settled.pop("Resolve-DefenseClawCodexManagedHooksStateCopySettled")
    assert set(settled) == set(_SETTLED_CALLERS), sorted(settled)
    for name, mode in _SETTLED_CALLERS.items():
        calls = re.findall(r"Resolve-DefenseClawCodexManagedHooksStateCopySettled([^\n]*)", settled[name])
        assert calls, name
        for call in calls:
            assert (" -Strict" in call) == (mode == "strict"), (name, call)


def test_the_settled_resolver_is_the_plain_one_off_the_standalone_profile() -> None:
    body = _function_body(_text(), "Resolve-DefenseClawCodexManagedHooksStateCopySettled")
    body = body[body.index("#>") :]
    guard = body.index("Test-DefenseClawStandaloneProfile")
    assert guard < body.index("Wait-DefenseClawCodexManagedHooksStateSettled")
    assert "return (Resolve-DefenseClawCodexManagedHooksStateCopy -Path $Path)" in body[guard:]


def test_the_wait_is_bounded_and_refuses_with_a_named_reason() -> None:
    text = _text()
    assert "$script:CodexStateSettleSeconds = 30" in text
    body = _function_body(text, "Wait-DefenseClawCodexManagedHooksStateSettled")
    assert "[DateTime]::UtcNow" in body and "Start-Sleep -Milliseconds 100" in body
    assert "'codex_state_unsettled: " in body
    assert "Format-DefenseClawSetupAction -Action '/repair'" in body


_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case, [string]$Call = 'assert', [int]$Standalone = 1)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Resolve-DefenseClawCodexManagedHooksStateCopy', 'Get-DefenseClawCodexManagedHooksWriterCounter', 'Wait-DefenseClawCodexManagedHooksStateSettled', 'Resolve-DefenseClawCodexManagedHooksStateCopySettled', 'Assert-DefenseClawCodexManagedHooksStateFile')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing $name" }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$script:CodexStateSettleSeconds = 30
$script:SystemSID = 'S-1-5-18'; $script:AdministratorsSID = 'S-1-5-32-544'; $script:TrustedInstallerSID = 'S-1-5-80'; $script:UsersSID = 'S-1-5-32-545'
$script:judged = [Collections.Generic.List[string]]::new()
$script:events = [Collections.Generic.List[string]]::new()
function Test-DefenseClawStandaloneProfile { [bool]$Standalone }
function Write-DefenseClawResilienceEvent { param([string]$Marker, [hashtable]$Fields) $script:events.Add($Marker + ': ' + $Fields['reason']) }
function Assert-DefenseClawCodexManagedHooksStateFilePreflight { param($Layout) }
function New-DefenseClawRequiredRights { param($Kind) 'rights' }
function Format-DefenseClawSetupAction { param([string]$Action) "Setup $Action" }
function Assert-DefenseClawPathAcl { param([string]$Path) $script:judged.Add($Path) }
$state = Join-Path $Scratch '.defenseclaw-managed-hooks.state'
$lock = Join-Path $Scratch '.defenseclaw-managed-hooks.writer.lock'
function Set-Counter([int]$Size) { [IO.File]::WriteAllBytes($lock, [byte[]]::new($Size)) }
# A second process plays the writer: it ends the transaction after a delay by
# putting the hook copy of the end value in place and then making the counter even.
function Start-Writer([int]$DelayMs, [string]$Copy, [int]$End) {
    $command = "Start-Sleep -Milliseconds $DelayMs; Set-Content -LiteralPath '$Copy' -Value x -NoNewline; [IO.File]::WriteAllBytes('$lock', [byte[]]::new($End))"
    $start = @{ FilePath = (Get-Process -Id $PID).Path; ArgumentList = @('-NoLogo', '-NoProfile', '-Command', $command); PassThru = $true }
    if ($IsWindows) { $start['WindowStyle'] = 'Hidden' }
    Start-Process @start
}
$writer = $null
switch ($Case) {
    'settled' { Set-Counter 2; Set-Content -LiteralPath "$state.2" -Value x -NoNewline }
    'missing' { Set-Counter 2 }
    'writer-ends' { Set-Counter 3; $writer = Start-Writer 1500 "$state.4" 4 }
    'writer-stopped' { Set-Counter 3; $script:CodexStateSettleSeconds = 2 }
    'writer-stopped-after-copy' { Set-Counter 3; $script:CodexStateSettleSeconds = 2; Set-Content -LiteralPath "$state.4" -Value x -NoNewline }
    'no-lock' { Set-Content -LiteralPath $state -Value x -NoNewline }
}
$threw = ''
$resolved = ''
$sw = [Diagnostics.Stopwatch]::StartNew()
try {
    switch ($Call) {
        'assert' { Assert-DefenseClawCodexManagedHooksStateFile -Layout @{ CodexManagedHooksStatePath = $state } }
        'strict' { $resolved = Split-Path (Resolve-DefenseClawCodexManagedHooksStateCopySettled -Strict -Path $state) -Leaf }
        'soft' { $resolved = Split-Path (Resolve-DefenseClawCodexManagedHooksStateCopySettled -Path $state) -Leaf }
    }
}
catch { $threw = $_.Exception.Message }
$sw.Stop()
if ($null -ne $writer) { $writer.WaitForExit(20000) | Out-Null }
[pscustomobject]@{
    threw = $threw
    seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    resolved = $resolved
    judged = @($script:judged | ForEach-Object { Split-Path $_ -Leaf })
    events = @($script:events)
} | ConvertTo-Json -Compress
"""


def _run(tmp_path: Path, case: str, call: str = "assert", standalone: bool = True) -> dict:
    engine = shutil.which("pwsh")
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "codex-state-settle.ps1"
    harness.write_text(_HARNESS, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Scratch", str(scratch), "-Case", case,
         "-Call", call, "-Standalone", "1" if standalone else "0"],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_a_settled_counter_is_judged_at_once_on_the_copy_it_names(tmp_path: Path) -> None:
    result = _run(tmp_path, "settled")
    assert result["threw"] == "", result
    assert result["judged"] == [".defenseclaw-managed-hooks.state.2"], result
    assert result["seconds"] < 3, result
    assert result["events"] == [], result  # a settled counter is not waited for


def test_no_writer_lock_means_the_fixed_name_of_the_earlier_release(tmp_path: Path) -> None:
    result = _run(tmp_path, "no-lock")
    assert result["threw"] == "", result
    assert result["judged"] == [".defenseclaw-managed-hooks.state"], result


def test_an_even_counter_without_its_copy_is_still_a_missing_state_at_once(tmp_path: Path) -> None:
    result = _run(tmp_path, "missing")
    assert result["threw"].startswith("DefenseClaw Codex managed-hooks state is missing: "), result
    assert result["threw"].endswith(".defenseclaw-managed-hooks.state.2"), result
    assert result["judged"] == [], result
    assert result["seconds"] < 3, result


def test_a_writer_that_ends_inside_the_bound_is_waited_for(tmp_path: Path) -> None:
    result = _run(tmp_path, "writer-ends")
    assert result["threw"] == "", result
    assert result["judged"] == [".defenseclaw-managed-hooks.state.4"], result
    assert result["seconds"] >= 1.0, result
    # The wait is logged with its length, so a run that had to wait shows it.
    assert len(result["events"]) == 1, result
    assert result["events"][0].startswith("defenseclaw_accept: a Codex writer transaction was open; the state check waited "), result
    assert result["events"][0].endswith(" ms for counter 4"), result


def test_a_writer_that_never_ends_is_refused_by_name_and_nothing_is_judged(tmp_path: Path) -> None:
    result = _run(tmp_path, "writer-stopped")
    assert result["threw"].startswith("codex_state_unsettled: "), result
    assert "stayed at 3 (odd: a transaction is open) for 2 seconds" in result["threw"], result
    assert "Next step: run Setup /repair again" in result["threw"], result
    assert result["judged"] == [], result
    assert 2 <= result["seconds"] < 10, result


def test_a_writer_that_stopped_after_its_copy_left_the_state_the_hook_reads(tmp_path: Path) -> None:
    result = _run(tmp_path, "writer-stopped-after-copy")
    assert result["threw"] == "", result
    assert result["judged"] == [".defenseclaw-managed-hooks.state.4"], result
    assert 2 <= result["seconds"] < 10, result


@pytest.mark.parametrize("call", ["strict", "soft"])
def test_a_caller_that_resolves_the_copy_waits_for_a_writer_that_ends(tmp_path: Path, call: str) -> None:
    # Review S1: the copy of the end value, not the copy of "odd + 1" that is not there yet.
    result = _run(tmp_path, "writer-ends", call=call)
    assert result["threw"] == "", result
    assert result["resolved"] == ".defenseclaw-managed-hooks.state.4", result
    assert result["seconds"] >= 1.0, result
    assert len(result["events"]) == 1, result


def test_a_strict_caller_refuses_a_writer_that_never_ends_by_name(tmp_path: Path) -> None:
    result = _run(tmp_path, "writer-stopped", call="strict")
    assert result["threw"].startswith("codex_state_unsettled: "), result
    assert result["resolved"] == "", result


def test_a_soft_caller_falls_back_to_the_plain_resolver_for_a_writer_that_never_ends(tmp_path: Path) -> None:
    result = _run(tmp_path, "writer-stopped", call="soft")
    assert result["threw"] == "", result
    assert result["resolved"] == ".defenseclaw-managed-hooks.state.4", result
    assert 2 <= result["seconds"] < 10, result


@pytest.mark.parametrize("call", ["strict", "soft"])
def test_secure_client_resolves_at_once_without_a_wait(tmp_path: Path, call: str) -> None:
    # No writer lock transaction on Secure Client: the plain resolver, no wait.
    result = _run(tmp_path, "writer-stopped", call=call, standalone=False)
    assert result["threw"] == "", result
    assert result["resolved"] == ".defenseclaw-managed-hooks.state.4", result
    assert result["seconds"] < 1.5, result
    assert result["events"] == [], result
